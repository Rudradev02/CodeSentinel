"""Tests for Phase 20 backend API schema backwards compatibility."""

import pytest
from backend.app.schemas.callgraph import (
    CallGraphSummaryDTO,
    ContractCompositionSummaryDTO,
    ContractSummaryDTO,
)


def test_call_graph_summary_dto_backward_compat():
    """Verify CallGraphSummaryDTO serializes and deserializes without composition field (Phase 19 baseline)."""
    data = {
        "analysis_id": "snap-1234",
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
        "contracts": {
            "contracts_generated": 5,
            "preconditions_verified": 2,
            "postconditions_propagated": 3,
            "multi_hop_guards_resolved": 1,
            "contracts_widened": 0,
            "recursive_sccs_resolved": 0,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(data)
    assert dto.analysis_id == "snap-1234"
    assert dto.composition is None

    # Roundtrip JSON
    dumped = dto.model_dump(mode="json")
    assert dumped["composition"] is None


def test_call_graph_summary_dto_with_phase20_composition():
    """Verify CallGraphSummaryDTO properly models Phase 20 composition metrics."""
    data = {
        "analysis_id": "snap-phase20",
        "total_functions": 20,
        "total_call_edges": 30,
        "resolved_local": 25,
        "resolved_import": 5,
        "unresolved": 0,
        "resolution_rate": 1.0,
        "summarized_functions": 20,
        "unsummarized_functions": 0,
        "interprocedural_findings_count": 0,
        "max_call_depth_reached": 3,
        "composition": {
            "composition_edges_count": 12,
            "guarantees_propagated_count": 8,
            "requirements_satisfied_count": 5,
            "conflicts_detected_count": 1,
            "security_boundary_violations_count": 2,
            "exceptional_contracts_evaluated_count": 4,
            "refinement_invalidations_count": 6,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(data)
    assert dto.composition is not None
    assert dto.composition.composition_edges_count == 12
    assert dto.composition.security_boundary_violations_count == 2
    assert dto.composition.refinement_invalidations_count == 6
