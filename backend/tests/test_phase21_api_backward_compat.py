"""Tests for Phase 21 backend API schema backwards compatibility and incremental telemetry."""

import pytest
from backend.app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResultDTO,
    AnalysisSummaryDTO,
    IncrementalStatsDTO,
)
from backend.app.schemas.callgraph import (
    CallGraphSummaryDTO,
    IncrementalSummaryDTO,
)


def test_call_graph_summary_dto_backward_compat_without_incremental():
    """Verify CallGraphSummaryDTO serializes and deserializes without incremental field (Phase 20 baseline)."""
    data = {
        "analysis_id": "snap-phase20",
        "total_functions": 10,
        "total_call_edges": 15,
        "resolved_local": 10,
        "resolved_import": 3,
        "unresolved": 2,
        "resolution_rate": 0.866,
        "summarized_functions": 8,
        "unsummarized_functions": 2,
        "interprocedural_findings_count": 1,
        "max_call_depth_reached": 2,
    }
    dto = CallGraphSummaryDTO.model_validate(data)
    assert dto.analysis_id == "snap-phase20"
    assert dto.incremental is None

    dumped = dto.model_dump(mode="json")
    assert dumped["incremental"] is None


def test_call_graph_summary_dto_with_incremental_telemetry():
    """Verify CallGraphSummaryDTO handles Phase 21 incremental telemetry."""
    data = {
        "analysis_id": "snap-phase21",
        "total_functions": 15,
        "total_call_edges": 20,
        "resolved_local": 15,
        "resolved_import": 5,
        "unresolved": 0,
        "resolution_rate": 1.0,
        "summarized_functions": 15,
        "unsummarized_functions": 0,
        "interprocedural_findings_count": 0,
        "max_call_depth_reached": 2,
        "incremental": {
            "analysis_mode": "incremental",
            "files_discovered": 10,
            "files_reused": 8,
            "files_reanalyzed": 2,
            "cache_hits": 50,
            "cache_misses": 5,
            "hit_ratio": 0.909,
            "estimated_time_saved_seconds": 1.25,
            "invalidations_by_reason": {
                "DIRECT_CONTENT_CHANGE": 1,
                "TRANSITIVE_DEPENDENCY_CHANGE": 1,
            },
        },
    }
    dto = CallGraphSummaryDTO.model_validate(data)
    assert dto.incremental is not None
    assert dto.incremental.analysis_mode == "incremental"
    assert dto.incremental.files_reused == 8
    assert dto.incremental.hit_ratio == 0.909
    assert dto.incremental.invalidations_by_reason["DIRECT_CONTENT_CHANGE"] == 1


def test_analysis_request_mode_defaults_and_explicit():
    """Verify AnalysisRequest defaults mode to 'full' and accepts 'incremental'."""
    req_default = AnalysisRequest(path="tests/fixtures/sample_project")
    assert req_default.mode == "full"

    req_inc = AnalysisRequest(path="tests/fixtures/sample_project", mode="incremental")
    assert req_inc.mode == "incremental"


def test_analysis_result_dto_with_incremental_stats():
    """Verify AnalysisResultDTO models incremental_stats cleanly."""
    stats = IncrementalStatsDTO(
        analysis_mode="incremental",
        files_discovered=25,
        files_reused=20,
        files_reanalyzed=5,
        ast_hits=20,
        ast_misses=5,
        cfg_hits=60,
        cfg_misses=15,
        graph_hits=40,
        graph_misses=10,
        contract_hits=35,
        contract_misses=8,
        finding_hits=12,
        finding_recomputed=2,
        cache_hits=167,
        cache_misses=40,
        hit_ratio=0.806,
        estimated_time_saved_seconds=2.45,
        invalidations_by_reason={"DIRECT_CONTENT_CHANGE": 3, "CONTRACT_CHANGE": 2},
    )

    summary = AnalysisSummaryDTO(
        total_findings=5,
        total_files=25,
        total_loc=1500,
        duration_seconds=0.65,
    )

    result_dto = AnalysisResultDTO(
        id="snap-inc-001",
        repository_path="/workspace/test_repo",
        repository_name="test_repo",
        summary=summary,
        incremental_stats=stats,
    )

    dumped = result_dto.model_dump(mode="json")
    assert dumped["incremental_stats"]["files_reused"] == 20
    assert dumped["incremental_stats"]["hit_ratio"] == 0.806
    assert dumped["incremental_stats"]["invalidations_by_reason"]["CONTRACT_CHANGE"] == 2
