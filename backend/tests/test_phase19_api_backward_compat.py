"""Unit tests for Phase 19 Backend API and Snapshot Persistence backward compatibility."""

import pytest
from backend.app.schemas.callgraph import (
    CallGraphSummaryDTO,
    ContractSummaryDTO,
    PathSensitivitySummaryDTO,
)


def test_historical_snapshot_backward_compatibility():
    """Verify Phase 15-18 snapshots deserialize gracefully without contracts field."""
    legacy_payload = {
        "analysis_id": "snap-phase18-001",
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
        "path_sensitivity": {
            "cfg_blocks_analyzed": 50,
            "guards_evaluated": 20,
            "guarded_paths_pruned": 8,
            "paths_truncated_budget": 0,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(legacy_payload)
    assert dto.analysis_id == "snap-phase18-001"
    assert dto.path_sensitivity is not None
    assert dto.contracts is None


def test_phase19_snapshot_deserialization():
    """Verify Phase 19 snapshot with contracts metadata parses and serializes correctly."""
    phase19_payload = {
        "analysis_id": "snap-phase19-001",
        "total_functions": 180,
        "total_call_edges": 450,
        "resolved_local": 300,
        "resolved_import": 120,
        "unresolved": 30,
        "resolution_rate": 0.933,
        "summarized_functions": 175,
        "unsummarized_functions": 5,
        "interprocedural_findings_count": 12,
        "max_call_depth_reached": 5,
        "contracts": {
            "contracts_generated": 25,
            "preconditions_verified": 18,
            "postconditions_propagated": 12,
            "multi_hop_guards_resolved": 7,
            "contracts_widened": 2,
            "recursive_sccs_resolved": 3,
        },
    }
    dto = CallGraphSummaryDTO.model_validate(phase19_payload)
    assert dto.contracts is not None
    assert dto.contracts.contracts_generated == 25
    assert dto.contracts.preconditions_verified == 18
    assert dto.contracts.postconditions_propagated == 12
    assert dto.contracts.multi_hop_guards_resolved == 7
    assert dto.contracts.contracts_widened == 2
    assert dto.contracts.recursive_sccs_resolved == 3


def test_contract_summary_dto_defaults():
    """Verify default values in ContractSummaryDTO."""
    dto = ContractSummaryDTO()
    assert dto.contracts_generated == 0
    assert dto.preconditions_verified == 0
    assert dto.postconditions_propagated == 0
    assert dto.multi_hop_guards_resolved == 0
    assert dto.contracts_widened == 0
    assert dto.recursive_sccs_resolved == 0
