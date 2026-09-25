"""Domain models for Phase 19 Interprocedural Contracts and Function Summaries."""

from enum import Enum
import hashlib
import json
from typing import Any, Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.cfg.models import GuardCondition, PredicateOp, RefinementFact
from analyzer.dataflow.taint.models import SinkCategory, TaintState


class ContractVerificationStatus(str, Enum):
    """Formal verification state of a contract precondition or postcondition."""
    SATISFIED = "SATISFIED"          # Statically proven satisfied; safe to prune or refine
    VIOLATED = "VIOLATED"            # Statically proven violated; defect confirmed
    UNKNOWN = "UNKNOWN"              # Insufficient static information; conservative fallback
    INFEASIBLE = "INFEASIBLE"        # Contradictory path condition; path unreachable
    WIDENED = "WIDENED"              # Resource bounds exceeded; widened conservatively
    TRUNCATED = "TRUNCATED"          # Call depth or condition count truncated
    UNRESOLVED = "UNRESOLVED"        # Target function could not be resolved


class PreconditionKind(str, Enum):
    """Classification of caller obligations at a callee boundary."""
    TYPE_REFINEMENT = "TYPE_REFINEMENT"              # e.g. param must be int/float
    FORMAT_REFINEMENT = "FORMAT_REFINEMENT"          # e.g. param must be alphanumeric/numeric string
    NULLITY_REFINEMENT = "NULLITY_REFINEMENT"        # e.g. param must be non-null
    SANITIZER_CATEGORY = "SANITIZER_CATEGORY"        # e.g. param must have COMMAND_EXECUTE sanitizer


class PostconditionTrigger(str, Enum):
    """Caller-side observation triggering postcondition application."""
    RETURN_EQUALS_TRUE = "RETURN_EQUALS_TRUE"        # if f(x): or assert f(x)
    RETURN_EQUALS_FALSE = "RETURN_EQUALS_FALSE"      # if not f(x):
    RETURN_NOT_NONE = "RETURN_NOT_NONE"              # if f(x) is not None:
    RETURN_EXACT_CONST = "RETURN_EXACT_CONST"        # if f(x) == "SAFE":
    UNCONDITIONAL = "UNCONDITIONAL"                  # Normal return unconditionally produces fact


class SummaryPrecondition(BaseModel):
    """Requirement that a caller must satisfy to avoid triggering a callee sink."""
    target_param_index: int
    target_param_name: str
    target_field_name: Optional[str] = None
    kind: PreconditionKind
    required_type: Optional[str] = None
    required_sanitizer_category: Optional[SinkCategory] = None
    sink_category: Optional[SinkCategory] = None
    raw_condition: str = ""
    line: int = 0
    provenance_sink_id: Optional[str] = None


class SummaryPostcondition(BaseModel):
    """Guaranteed fact established upon function completion when trigger holds."""
    trigger: PostconditionTrigger
    trigger_literal: Optional[str] = None
    target_param_index: Optional[int] = None
    target_param_name: Optional[str] = None
    target_field_name: Optional[str] = None
    applies_to_return: bool = False
    produced_refinement: Optional[RefinementFact] = None
    produced_taint_state: Optional[TaintState] = None
    applicable_sanitizer_category: Optional[SinkCategory] = None
    confidence: str = "HIGH"
    provenance_line: int = 0


class ConditionalTaintEffect(BaseModel):
    """Taint transfer or sanitizer effect valid only under a specific path condition."""
    from_param_index: int
    to_return: bool = False
    to_sink_category: Optional[SinkCategory] = None
    to_field_name: Optional[str] = None
    sanitizer_category: Optional[SinkCategory] = None
    governing_path_condition: Optional[str] = None
    governing_guards: list[GuardCondition] = Field(default_factory=list)
    taint_state: TaintState = TaintState.TAINTED


class FunctionContract(BaseModel):
    """Formal interprocedural contract for a function scope."""
    qualified_name: str
    file_path: str
    context_id: str = "ROOT"
    is_pure: bool = False
    preconditions: list[SummaryPrecondition] = Field(default_factory=list)
    postconditions: list[SummaryPostcondition] = Field(default_factory=list)
    conditional_effects: list[ConditionalTaintEffect] = Field(default_factory=list)
    is_widened: bool = False
    extraction_truncated: bool = False
    contract_hash: str = ""

    def compute_hash(self) -> str:
        """Deterministic SHA-256 hash of the contract contents."""
        data = {
            "qn": self.qualified_name,
            "ctx": self.context_id,
            "pure": self.is_pure,
            "pre": [p.model_dump(mode="json") for p in self.preconditions],
            "post": [p.model_dump(mode="json") for p in self.postconditions],
            "effects": [e.model_dump(mode="json") for e in self.conditional_effects],
            "widened": self.is_widened,
            "truncated": self.extraction_truncated,
        }
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
