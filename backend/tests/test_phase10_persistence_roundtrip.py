"""Tests for Phase 10 canonical AnalysisResult persistence round-trip and secret redaction."""

from pathlib import Path
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from backend.app.models.repository import Repository
from backend.app.services.persistence import PersistenceService, _sanitize_snippet

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project"


@pytest.mark.asyncio
async def test_full_pipeline_persistence_roundtrip(db_session: AsyncSession):
    """Run real analysis pipeline on fixture, persist snapshot, and reconstruct with 100% fidelity."""
    # 1. Register repository
    repo = Repository(
        id=str(uuid.uuid4()),
        name="sample_project",
        path=str(FIXTURE_PATH.resolve()),
    )
    db_session.add(repo)
    await db_session.commit()

    # 2. Run analysis pipeline
    config = AnalysisConfig()
    pipeline = AnalysisPipeline(analysis_config=config)
    original_result = pipeline.run(target_path=FIXTURE_PATH, analysis_config=config)

    assert original_result.status.value == "COMPLETED"
    assert len(original_result.architecture_findings) > 0
    assert original_result.health is not None

    # 3. Persist analysis snapshot
    config_dict = {"max_component_depth": 2}
    snapshot = await PersistenceService.save_analysis_snapshot(
        db=db_session,
        repository_id=repo.id,
        result=original_result,
        config_dict=config_dict,
    )

    assert snapshot.id == original_result.id
    assert snapshot.repository_id == repo.id
    assert snapshot.overall_score == original_result.health.overall_score
    assert snapshot.overall_grade == original_result.health.overall_grade
    assert snapshot.architecture_score == original_result.health.architecture_health.score
    assert snapshot.security_score == original_result.health.security_posture.score

    # 4. Retrieve snapshot from persistence service
    retrieved = await PersistenceService.get_analysis_snapshot(
        db=db_session,
        repository_id=repo.id,
        analysis_id=snapshot.id,
    )
    assert retrieved is not None
    assert len(retrieved.findings) == len(original_result.security_findings + original_result.architecture_findings)
    assert len(retrieved.components) == len(original_result.graph.component_graph.nodes)
    assert len(retrieved.component_edges) == len(original_result.graph.component_graph.edges)

    # 5. Reconstruct canonical AnalysisResultDTO
    dto = PersistenceService.reconstruct_analysis_dto(
        snapshot=retrieved,
        repo_path=FIXTURE_PATH,
        repo_name=repo.name,
    )

    # 6. Verify full-fidelity preservation
    assert dto.id == original_result.id
    assert dto.status == "COMPLETED"
    assert dto.repository_name == "sample_project"

    # Health score fidelity
    assert dto.health is not None
    assert dto.health.overall_score == original_result.health.overall_score
    assert dto.health.overall_grade == original_result.health.overall_grade
    assert dto.health.architecture_health.score == original_result.health.architecture_health.score
    assert dto.health.architecture_health.grade == original_result.health.architecture_health.grade
    assert dto.health.security_posture.score == original_result.health.security_posture.score
    assert dto.health.security_posture.grade == original_result.health.security_posture.grade

    # Deductions count & items
    orig_total_deductions = len(original_result.health.architecture_health.deductions) + len(original_result.health.security_posture.deductions)
    dto_total_deductions = len(dto.health.architecture_health.deductions) + len(dto.health.security_posture.deductions)
    assert dto_total_deductions == orig_total_deductions

    # Findings fidelity
    assert len(dto.findings) == len(original_result.architecture_findings)
    dto_rule_ids = {f.rule_id for f in dto.findings}
    orig_rule_ids = {f.rule_id for f in original_result.architecture_findings}
    assert dto_rule_ids == orig_rule_ids

    # Component graph fidelity
    assert dto.component_graph is not None
    assert len(dto.component_graph.nodes) == len(original_result.graph.component_graph.nodes)
    assert len(dto.component_graph.edges) == len(original_result.graph.component_graph.edges)
    assert dto.component_graph.circular_components_count == original_result.graph.component_graph.circular_components_count

    # Check node metrics preserved
    orig_node_map = {n.id: n for n in original_result.graph.component_graph.nodes}
    for dto_node in dto.component_graph.nodes:
        assert dto_node.id in orig_node_map
        orig_node = orig_node_map[dto_node.id]
        assert dto_node.coupling.afferent == orig_node.metrics.afferent_coupling
        assert dto_node.coupling.efferent == orig_node.metrics.efferent_coupling
        assert abs(dto_node.coupling.instability - orig_node.metrics.instability) < 0.001


def test_secret_snippet_sanitization():
    """Verify that secret findings have sensitive credentials redacted before database persistence."""
    raw_snippet = 'API_KEY = "sk-live-secret-super-sensitive-12345"'
    redacted = _sanitize_snippet("SEC-PY-001", raw_snippet)
    assert "sk-live-secret-super-sensitive-12345" not in redacted
    assert "[REDACTED_SECRET]" in redacted

    # Non-secret finding snippets should remain untouched
    clean_snippet = "import os\nfrom pathlib import Path"
    assert _sanitize_snippet("ARC-001", clean_snippet) == clean_snippet
