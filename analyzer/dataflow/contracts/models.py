"""Domain models for Phase 19 Interprocedural Contracts and Function Summaries."""

from enum import Enum
import hashlib
import json
from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator

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
    PARAM_IS_NOT_NONE = "PARAM_IS_NOT_NONE"          # Parameter proven non-null
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

    @property
    def parameter_index(self) -> int:
        return self.target_param_index

    @property
    def parameter_name(self) -> str:
        return self.target_param_name

    @property
    def precondition_kind(self) -> PreconditionKind:
        return self.kind


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

    @property
    def parameter_index(self) -> Optional[int]:
        return self.target_param_index

    @property
    def parameter_name(self) -> Optional[str]:
        return self.target_param_name


class EffectKind(str, Enum):
    """Classification of conditional taint effects."""
    PROPAGATES_TAINT = "PROPAGATES_TAINT"
    CLEARS_TAINT = "CLEARS_TAINT"
    APPLIES_SANITIZER = "APPLIES_SANITIZER"


class ConditionalTaintEffect(BaseModel):
    """Taint transfer or sanitizer effect valid only under a specific path condition."""
    from_param_index: int = 0
    to_return: bool = False
    to_sink_category: Optional[SinkCategory] = None
    to_field_name: Optional[str] = None
    sanitizer_category: Optional[SinkCategory] = None
    governing_path_condition: Optional[str] = None
    governing_guards: list[GuardCondition] = Field(default_factory=list)
    taint_state: TaintState = TaintState.TAINTED
    effect_kind: EffectKind = EffectKind.PROPAGATES_TAINT
    clears_taint: bool = False
    sanitizer_applied: Optional[str] = None
    confidence: str = "HIGH"

    @model_validator(mode="before")
    @classmethod
    def _remap_compatibility_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "governing_condition" in data and "governing_path_condition" not in data:
                data["governing_path_condition"] = data["governing_condition"]
            if "parameter_index" in data and "from_param_index" not in data:
                data["from_param_index"] = data["parameter_index"]
        return data

    @property
    def parameter_index(self) -> int:
        return self.from_param_index

    @property
    def governing_condition(self) -> Optional[str]:
        return self.governing_path_condition


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

    @property
    def contract_id(self) -> str:
        return self.contract_hash or f"{self.qualified_name}::{self.context_id}"

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
