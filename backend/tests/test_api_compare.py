"""Tests for POST /api/v1/compare differential comparison endpoint (Phase 9)."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisResult, RepositoryInfo
from backend.app.main import app
from backend.app.schemas.comparison import ComparisonResponseDTO


@pytest.fixture
def client():
    """Create test client for FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def _make_result(repo_name: str, findings: list[Finding], commit: str = "c1") -> dict:
    repo = RepositoryInfo(
        name=repo_name,
        local_path="/repo",
        total_files=2,
        detected_languages={"python": 2},
        commit_hash=commit,
    )
    res = AnalysisResult(
        repository=repo,
        security_findings=findings,
    )
    return res.model_dump(mode="json")


def test_compare_with_direct_json(client: TestClient):
    """Verify comparing two JSON results via direct payload objects."""
    f_common = Finding(
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secret",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app.py", line_start=10),
        code_snippet="secret = 'abc'",
        description="Found secret",
        remediation="Use env",
    )
    f_resolved = Finding(
        rule_id="SEC-PY-002",
        rule_name="Unsafe Exec",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="exec.py", line_start=5),
        code_snippet="exec(user_code)",
        description="Exec called",
        remediation="Remove exec",
    )
    f_new = Finding(
        rule_id="SEC-PY-003",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="db.py", line_start=20),
        code_snippet="query = f'SELECT {user_id}'",
        description="Raw interpolation",
        remediation="Use params",
    )

    base_json = _make_result("repo-a", [f_common, f_resolved], commit="commit-1")
    curr_json = _make_result("repo-a", [f_common, f_new], commit="commit-2")

    response = client.post(
        "/api/v1/compare",
        json={
            "baseline_json": base_json,
            "current_json": curr_json,
        },
    )
    assert response.status_code == 200
    data = response.json()
    validated = ComparisonResponseDTO.model_validate(data)

    assert validated.summary.total_baseline == 2
    assert validated.summary.total_current == 2
    assert validated.summary.unchanged_count == 1
    assert validated.summary.resolved_count == 1
    assert validated.summary.new_count == 1

    transitions = {df.finding.rule_id: df.transition for df in validated.findings}
    assert transitions["SEC-PY-001"] == "UNCHANGED"
    assert transitions["SEC-PY-002"] == "RESOLVED"
    assert transitions["SEC-PY-003"] == "NEW"


def test_compare_with_file_paths(client: TestClient, tmp_path: Path):
    """Verify comparing two JSON results via filesystem paths."""
    base_file = tmp_path / "base.json"
    curr_file = tmp_path / "curr.json"

    f1 = Finding(
        rule_id="SEC-PY-001",
        rule_name="Secret",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app.py", line_start=1),
        code_snippet="k = 1",
        description="d",
        remediation="r",
    )
    base_file.write_text(AnalysisResult(repository=RepositoryInfo(name="t", local_path=str(tmp_path)), security_findings=[f1]).model_dump_json(), encoding="utf-8")
    curr_file.write_text(AnalysisResult(repository=RepositoryInfo(name="t", local_path=str(tmp_path)), security_findings=[]).model_dump_json(), encoding="utf-8")

    response = client.post(
        "/api/v1/compare",
        json={
            "baseline_path": str(base_file),
            "current_path": str(curr_file),
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["resolved_count"] == 1
    assert data["summary"]["new_count"] == 0


def test_compare_missing_inputs(client: TestClient):
    """Verify 400 when neither json nor path are provided."""
    response = client.post("/api/v1/compare", json={})
    assert response.status_code == 400
