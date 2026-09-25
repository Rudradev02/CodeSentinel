"""Pydantic schemas for Phase 15 Call Graph Intelligence."""

from typing import Optional
from pydantic import BaseModel, Field


class TypeResolutionSummaryDTO(BaseModel):
    types_inferred: int = 0
    type_aware_edges: int = 0
    ambiguous_receivers: int = 0
    confidence_distribution: dict[str, int] = Field(default_factory=dict)


class ContextSensitivitySummaryDTO(BaseModel):
    total_contexts: int = 0
    max_depth_reached: int = 0
    contexts_truncated: int = 0
    truncation_reasons: list[str] = Field(default_factory=list)


class AliasAnalysisSummaryDTO(BaseModel):
    """Alias, points-to, and field-sensitivity analysis metrics (Phase 17)."""
    abstract_objects_count: int = Field(default=0, ge=0)
    alias_bindings_count: int = Field(default=0, ge=0)
    field_edges_count: int = Field(default=0, ge=0)
    ambiguous_points_to_count: int = Field(default=0, ge=0)
    truncated_points_to_count: int = Field(default=0, ge=0)


class PathSensitivitySummaryDTO(BaseModel):
    """Path-sensitivity, CFG, and guard analysis metrics (Phase 18)."""
    cfg_blocks_analyzed: int = Field(default=0, ge=0)
    guards_evaluated: int = Field(default=0, ge=0)
    guarded_paths_pruned: int = Field(default=0, ge=0)
    paths_truncated_budget: int = Field(default=0, ge=0)


class ContractSummaryDTO(BaseModel):
    """Path-sensitive interprocedural contract analysis metrics (Phase 19)."""
    contracts_generated: int = Field(default=0, ge=0)
    preconditions_verified: int = Field(default=0, ge=0)
    postconditions_propagated: int = Field(default=0, ge=0)
    multi_hop_guards_resolved: int = Field(default=0, ge=0)
    contracts_widened: int = Field(default=0, ge=0)
    recursive_sccs_resolved: int = Field(default=0, ge=0)


class ContractCompositionSummaryDTO(BaseModel):
    """Project-wide contract composition and security boundary metrics (Phase 20)."""
    composition_edges_count: int = Field(default=0, ge=0)
    guarantees_propagated_count: int = Field(default=0, ge=0)
    requirements_satisfied_count: int = Field(default=0, ge=0)
    conflicts_detected_count: int = Field(default=0, ge=0)
    security_boundary_violations_count: int = Field(default=0, ge=0)
    exceptional_contracts_evaluated_count: int = Field(default=0, ge=0)
    refinement_invalidations_count: int = Field(default=0, ge=0)


class CallGraphSummaryDTO(BaseModel):
    """Call graph analysis metrics and summary for a snapshot."""

    analysis_id: str = Field(..., description="Unique analysis snapshot ID")
    total_functions: int = Field(default=0, ge=0, description="Total functions discovered")
    total_call_edges: int = Field(default=0, ge=0, description="Total call sites evaluated")
    resolved_local: int = Field(default=0, ge=0, description="Edges resolved within same file")
    resolved_import: int = Field(default=0, ge=0, description="Edges resolved across imports")
    unresolved: int = Field(default=0, ge=0, description="External or unresolved call edges")
    resolution_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of resolved calls")
    summarized_functions: int = Field(default=0, ge=0, description="Functions with generated summaries")
    unsummarized_functions: int = Field(default=0, ge=0, description="Functions exceeding bounds or skipped")
    interprocedural_findings_count: int = Field(default=0, ge=0, description="Findings discovered via cross-function taint")
    max_call_depth_reached: int = Field(default=0, ge=0, description="Max call depth reached in propagation")
    type_resolution: Optional[TypeResolutionSummaryDTO] = None
    context_sensitivity: Optional[ContextSensitivitySummaryDTO] = None
    alias_analysis: Optional[AliasAnalysisSummaryDTO] = None
    path_sensitivity: Optional[PathSensitivitySummaryDTO] = None
    contracts: Optional[ContractSummaryDTO] = None
    composition: Optional[ContractCompositionSummaryDTO] = None

