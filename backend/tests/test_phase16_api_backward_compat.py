"""Unit tests for Phase 16 Backend API and Snapshot Persistence backward compatibility."""

import pytest
from backend.app.schemas.callgraph import (
    CallGraphSummaryDTO,
    ContextSensitivitySummaryDTO,
    TypeResolutionSummaryDTO,
)


def test_phase15_snapshot_backward_compatibility():
    """Verify Phase 15 snapshot JSON can be deserialized without type_resolution or context_sensitivity."""
    phase15_payload = {
        "analysis_id": "snap-phase15-001",
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
    }
    dto = CallGraphSummaryDTO.model_validate(phase15_payload)
    assert dto.analysis_id == "snap-phase15-001"
    assert dto.total_functions == 120
    assert dto.type_resolution is None
    assert dto.context_sensitivity is None


def test_phase16_snapshot_deserialization():
    """Verify Phase 16 snapshot with type and context metadata parses correctly."""
    phase16_payload = {
        "analysis_id": "snap-phase16-001",
        "total_functions": 150,
        "total_call_edges": 400,
        "resolved_local": 250,
        "resolved_import": 120,
        "unresolved": 30,
        "resolution_rate": 0.925,
        "summarized_functions": 148,
        "unsummarized_functions": 2,
        "interprocedural_findings_count": 12,
        "max_call_depth_reached": 5,
        "type_resolution": {
            "types_inferred": 85,
            "type_aware_edges": 110,
            "ambiguous_receivers": 4,
            "confidence_distribution": {"KNOWN": 95, "LIKELY": 15},
        },
        "context_sensitivity": {
            "total_contexts": 64,
            "max_depth_reached": 2,
            "contexts_truncated": 1,
            "truncation_reasons": ["MAX_CONTEXTS_PER_FUNCTION"],
        },
    }
    dto = CallGraphSummaryDTO.model_validate(phase16_payload)
    assert dto.analysis_id == "snap-phase16-001"
    assert dto.type_resolution is not None
    assert dto.type_resolution.types_inferred == 85
    assert dto.type_resolution.type_aware_edges == 110
    assert dto.type_resolution.ambiguous_receivers == 4
    assert dto.type_resolution.confidence_distribution["KNOWN"] == 95

    assert dto.context_sensitivity is not None
    assert dto.context_sensitivity.total_contexts == 64
    assert dto.context_sensitivity.max_depth_reached == 2
    assert dto.context_sensitivity.contexts_truncated == 1
    assert "MAX_CONTEXTS_PER_FUNCTION" in dto.context_sensitivity.truncation_reasons
