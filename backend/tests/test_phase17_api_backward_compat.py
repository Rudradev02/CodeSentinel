"""Unit tests for Phase 17 Backend API and Snapshot Persistence backward compatibility."""

import pytest
from backend.app.schemas.callgraph import (
    AliasAnalysisSummaryDTO,
    CallGraphSummaryDTO,
    ContextSensitivitySummaryDTO,
    TypeResolutionSummaryDTO,
)


def test_phase15_and_16_snapshot_backward_compatibility():
    """Verify Phase 15/16 snapshots deserialize gracefully without alias_analysis."""
    legacy_payload = {
        "analysis_id": "snap-phase16-001",
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
    }
    dto = CallGraphSummaryDTO.model_validate(legacy_payload)
    assert dto.analysis_id == "snap-phase16-001"
    assert dto.type_resolution is not None
    assert dto.context_sensitivity is not None
    assert dto.alias_analysis is None


def test_phase17_snapshot_deserialization():
    """Verify Phase 17 snapshot with alias_analysis metadata parses correctly."""
    phase17_payload = {
        "analysis_id": "snap-phase17-001",
        "total_functions": 160,
        "total_call_edges": 420,
        "resolved_local": 280,
        "resolved_import": 110,
        "unresolved": 30,
        "resolution_rate": 0.928,
        "summarized_functions": 158,
        "unsummarized_functions": 2,
        "interprocedural_findings_count": 14,
        "max_call_depth_reached": 5,
        "type_resolution": {
            "types_inferred": 90,
            "type_aware_edges": 125,
            "ambiguous_receivers": 2,
            "confidence_distribution": {"KNOWN": 105, "LIKELY": 20},
        },
        "context_sensitivity": {
            "total_contexts": 70,
            "max_depth_reached": 2,
            "contexts_truncated": 0,
            "truncation_reasons": [],
        },
        "alias_analysis": {
            "abstract_objects_count": 48,
            "alias_bindings_count": 32,
            "field_edges_count": 24,
            "ambiguous_points_to_count": 3,
            "truncated_points_to_count": 0,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(phase17_payload)
    assert dto.analysis_id == "snap-phase17-001"
    assert dto.alias_analysis is not None
    assert dto.alias_analysis.abstract_objects_count == 48
    assert dto.alias_analysis.alias_bindings_count == 32
    assert dto.alias_analysis.field_edges_count == 24
    assert dto.alias_analysis.ambiguous_points_to_count == 3
    assert dto.alias_analysis.truncated_points_to_count == 0
