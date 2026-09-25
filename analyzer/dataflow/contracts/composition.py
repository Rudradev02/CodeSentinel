"""Domain models for Phase 20 Project-Wide Contract Composition and Compatibility."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.cfg.models import RefinementFact
from analyzer.dataflow.contracts.models import PreconditionKind
from analyzer.dataflow.taint.models import SinkCategory, TaintState


class CompatibilityState(str, Enum):
    """Compatibility state between an upstream contract guarantee and a downstream requirement."""
    SATISFIED = "SATISFIED"          # Guarantee strictly proves requirement under path condition
    VIOLATED = "VIOLATED"            # Guarantee strictly contradicts requirement (confirmed incompatibility)
    CONFLICTING = "CONFLICTING"      # Multiple guarantees along same path provide opposing facts
    UNKNOWN = "UNKNOWN"              # Insufficient static information (UNKNOWN != SAFE)
    INFEASIBLE = "INFEASIBLE"        # Governing path condition is contradictory
    WIDENED = "WIDENED"              # Bounded iteration exceeded; conservatively widened
    TRUNCATED = "TRUNCATED"          # Call depth or composition budget exceeded
    UNRESOLVED = "UNRESOLVED"        # Target function definition could not be resolved


class ContractGuarantee(BaseModel):
    """Fact established by an upstream producer function."""
    producer_qn: str
    producer_file: str
    producer_line: int
    target_var_name: str
    target_field_name: Optional[str] = None
    refinement: Optional[RefinementFact] = None
    taint_state: TaintState = TaintState.UNKNOWN
    sanitizer_category: Optional[SinkCategory] = None
    path_condition: Optional[str] = None
    epoch: int = 0
    provenance_kind: str = "DIRECT_CONTRACT"


class ContractRequirement(BaseModel):
    """Obligation demanded by a downstream consumer function or sink."""
    consumer_qn: str
    consumer_file: str
    consumer_line: int
    target_param_index: int
    target_param_name: str
    target_field_name: Optional[str] = None
    required_kind: PreconditionKind
    required_type: Optional[str] = None
    required_sanitizer: Optional[SinkCategory] = None
    sink_category: Optional[SinkCategory] = None


class ContractCompositionEdge(BaseModel):
    """Link between a producer guarantee and a consumer requirement."""
    guarantee: ContractGuarantee
    requirement: ContractRequirement
    compatibility: CompatibilityState
    governing_path: Optional[str] = None
    details: str = ""


class ContractConflict(BaseModel):
    """Record of contradictory contract facts along the same active path."""
    variable_name: str
    guarantees: list[ContractGuarantee] = Field(default_factory=list)
    conflict_reason: str
    path_condition: Optional[str] = None


class ContractCompositionResult(BaseModel):
    """Aggregated contract composition result across an interprocedural call chain."""
    edges: list[ContractCompositionEdge] = Field(default_factory=list)
    conflicts: list[ContractConflict] = Field(default_factory=list)
    overall_compatibility: CompatibilityState = CompatibilityState.UNKNOWN
    composition_depth: int = 0
    is_widened: bool = False
    is_truncated: bool = False
