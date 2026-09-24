"""Unit tests for Phase 18 Backend API and Snapshot Persistence backward compatibility."""

import pytest
from backend.app.schemas.callgraph import (
    AliasAnalysisSummaryDTO,
    CallGraphSummaryDTO,
    ContextSensitivitySummaryDTO,
    PathSensitivitySummaryDTO,
    TypeResolutionSummaryDTO,
)


def test_historical_snapshot_backward_compatibility():
    """Verify Phase 15-17 snapshots deserialize gracefully without path_sensitivity."""
    legacy_payload = {
        "analysis_id": "snap-phase17-001",
        "total_functions": 120,
        "total_call_edges": 350,
        "resolved_local": 200,
        "resolved_import": 100,
        "unresolved": 50,
        "resolution_rate": 0.857,
        "summarized_functions": 115,
        "unsummarized_functions": 5,
        "interprocedural_findings_count": 8,
        "max_call_depth_reached": 4,
        "type_resolution": {
            "types_inferred": 85,
            "type_aware_edges": 110,
            "ambiguous_receivers": 4,
            "confidence_distribution": {"KNOWN": 95},
        },
        "context_sensitivity": {
            "total_contexts": 64,
            "max_depth_reached": 2,
            "contexts_truncated": 0,
            "truncation_reasons": [],
        },
        "alias_analysis": {
            "abstract_objects_count": 42,
            "alias_bindings_count": 88,
            "field_edges_count": 25,
            "ambiguous_points_to_count": 1,
            "truncated_points_to_count": 0,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(legacy_payload)
    assert dto.analysis_id == "snap-phase17-001"
    assert dto.alias_analysis is not None
    assert dto.alias_analysis.abstract_objects_count == 42
    assert dto.path_sensitivity is None


def test_phase18_snapshot_deserialization():
    """Verify Phase 18 snapshot with path_sensitivity metadata parses and serializes correctly."""
    phase18_payload = {
        "analysis_id": "snap-phase18-001",
        "total_functions": 180,
        "total_call_edges": 450,
        "resolved_local": 300,
        "resolved_import": 120,
        "unresolved": 30,
        "resolution_rate": 0.933,
        "summarized_functions": 178,
        "unsummarized_functions": 2,
        "interprocedural_findings_count": 12,
        "max_call_depth_reached": 5,
        "type_resolution": {
            "types_inferred": 120,
            "type_aware_edges": 140,
            "ambiguous_receivers": 2,
            "confidence_distribution": {"KNOWN": 138, "LIKELY": 2},
        },
        "context_sensitivity": {
            "total_contexts": 96,
            "max_depth_reached": 2,
            "contexts_truncated": 0,
            "truncation_reasons": [],
        },
        "alias_analysis": {
            "abstract_objects_count": 64,
            "alias_bindings_count": 130,
            "field_edges_count": 40,
            "ambiguous_points_to_count": 0,
            "truncated_points_to_count": 0,
        },
        "path_sensitivity": {
            "cfg_blocks_analyzed": 512,
            "guards_evaluated": 48,
            "guarded_paths_pruned": 14,
            "paths_truncated_budget": 0,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(phase18_payload)
    assert dto.analysis_id == "snap-phase18-001"
    assert dto.path_sensitivity is not None
    assert dto.path_sensitivity.cfg_blocks_analyzed == 512
    assert dto.path_sensitivity.guards_evaluated == 48
    assert dto.path_sensitivity.guarded_paths_pruned == 14
    assert dto.path_sensitivity.paths_truncated_budget == 0

    serialized = dto.model_dump()
    assert "path_sensitivity" in serialized
    assert serialized["path_sensitivity"]["cfg_blocks_analyzed"] == 512
    assert serialized["path_sensitivity"]["guarded_paths_pruned"] == 14
