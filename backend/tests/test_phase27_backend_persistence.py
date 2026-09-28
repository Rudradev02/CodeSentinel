"""Test suite for Phase 27: Backend Compliance API & Persistence Hardening."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from analyzer.compliance.attestation import (
    AttestationPredicate,
    ScanAttestationStatement,
    sign_attestation,
)
from analyzer.compliance.evaluator import ComplianceEvaluator
from analyzer.compliance.models import ComplianceFramework
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.metadata import AnalysisMetadata
from analyzer.models.repository import RepositoryInfo
from analyzer.models.results import AnalysisResult, AnalysisStatus
from analyzer.models.summary import ArchitectureSummary, SecuritySummary
from backend.app.main import app
from backend.app.services.persistence import PersistenceService, _build_snapshot_entities


@pytest.fixture
def client():
    return TestClient(app)


def test_get_framework_controls_returns_phase27_provenance_and_mapping(client):
    """Verify GET /api/v1/compliance/frameworks/{id}/controls returns Phase 27 provenance and mapping fields."""
    response = client.get("/api/v1/compliance/frameworks/PCI_DSS_V4_0/controls")
    assert response.status_code == 200
    controls = response.json()
    assert len(controls) > 0

    first_ctrl = controls[0]
    assert "framework_version" in first_ctrl
    assert first_ctrl["framework_version"] != ""
    assert "mapping_type" in first_ctrl
    assert first_ctrl["mapping_type"] in ("DIRECT", "SUPPORTING", "PARTIAL", "INFERRED", "NOT_ASSESSABLE")
    assert "static_limitations" in first_ctrl
    assert isinstance(first_ctrl["static_limitations"], list)
    assert "provenance" in first_ctrl
    assert first_ctrl["provenance"] is not None
    assert "source_standard" in first_ctrl["provenance"]


def test_persistence_service_attaches_compliance_and_attestation_to_config():
    """Verify that PersistenceService embeds compliance suite and attestation into AnalysisSnapshot.configuration."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    suite = evaluator.assess_suite(findings=[], repository_path="test/repo")

    stmt = ScanAttestationStatement(
        subject=[{"name": "test/repo", "digest": "sha256:abc"}],
        predicate=AttestationPredicate(
            tool_name="CodeSentinel",
            tool_version="0.1.0",
            analysis_timestamp="2026-09-28T00:00:00Z",
            findings_merkle_root="merkle-root",
            suppressions_digest="",
        ),
    )
    envelope = sign_attestation(stmt, "test-secret-key")

    dummy_result = AnalysisResult(
        id="snap-p27-1",
        status=AnalysisStatus.SUCCESS,
        repository_path="test/repo",
        repository=RepositoryInfo(
            path="test/repo",
            name="test-repo",
            total_files=5,
            total_loc=100,
        ),
        metadata=AnalysisMetadata(
            engine_version="0.1.0",
            duration_seconds=1.5,
        ),
        findings=[],
        security_findings=[],
        architecture_findings=[],
        security_summary=SecuritySummary(total=0, critical=0, high=0, medium=0, low=0, info=0),
        architecture_summary=ArchitectureSummary(
            total_findings=0,
            circular_dependencies_count=0,
            layer_violations_count=0,
            god_components_count=0,
            unstable_dependencies_count=0,
        ),
        compliance=suite,
        attestation=envelope,
    )

    snapshot, findings, deductions, comps, edges = _build_snapshot_entities(
        repository_id="repo-1",
        result=dummy_result,
        config_dict={"custom_key": "val"},
    )

    assert snapshot.configuration is not None
    assert "custom_key" in snapshot.configuration
    assert "compliance" in snapshot.configuration
    assert "attestation" in snapshot.configuration
    assert snapshot.configuration["attestation"]["payloadType"] == "application/vnd.in-toto+json"
    assert "PCI_DSS_V4_0" in snapshot.configuration["compliance"]["framework_results"]
