"""Context-aware security evidence chain models for CodeSentinel (Phase 22).

These models capture structured, verifiable evidence trails linking a security finding
to its taint source, propagation steps, sanitizer evaluations, taint sinks, contract
precondition/postcondition evaluations, and security boundary compatibility checks.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class TaintSourceEvidence(BaseModel):
    """Evidence for the origin of untrusted input."""
    model_config = ConfigDict(frozen=True)

    source_category: str
    file_path: str
    line: int
    column: int = 0
    expression: str
    framework: Optional[str] = None


class PropagationStep(BaseModel):
    """Single step in a taint propagation trace."""
    model_config = ConfigDict(frozen=True)

    step_index: int
    file_path: str
    line: int
    column: int = 0
    operation: str = "ASSIGNMENT"  # "ASSIGNMENT", "CALL_ARG", "RETURN", "FIELD_ACCESS"
    from_symbol: Optional[str] = None
    to_symbol: Optional[str] = None
    taint_state: str = "TAINTED"
    is_interprocedural: bool = False
    callee_qn: Optional[str] = None
    contract_id: Optional[str] = None


class SanitizerEvidence(BaseModel):
    """Evidence for a sanitizer application and its category compatibility."""
    model_config = ConfigDict(frozen=True)

    sanitizer_id: str
    effective_categories: list[str] = Field(default_factory=list)
    file_path: str
    line: int
    expression: str
    is_category_compatible: bool = True
    incompatible_reason: Optional[str] = None


class TaintSinkEvidence(BaseModel):
    """Evidence for the sink where tainted data reaches."""
    model_config = ConfigDict(frozen=True)

    sink_category: str
    rule_id: str
    file_path: str
    line: int
    column: int = 0
    callee_name: str
    vulnerable_arg_index: int = 0
    parameter_binding_available: bool = False


class ContractEvaluationEvidence(BaseModel):
    """Evidence from a contract precondition/postcondition evaluation at a call site."""
    model_config = ConfigDict(frozen=True)

    call_site_file: str
    call_site_line: int
    caller_qn: str
    callee_qn: str
    contract_id: str
    evaluation_result: str = "UNKNOWN"  # "SATISFIED", "VIOLATED", "UNKNOWN", "WIDENED", "TRUNCATED"
    precondition_kind: Optional[str] = None
    postcondition_trigger: Optional[str] = None
    details: str = ""


class BoundaryEvaluationEvidence(BaseModel):
    """Evidence from a security boundary compatibility check."""
    model_config = ConfigDict(frozen=True)

    rule_id: str
    sink_category: str
    sanitizer_category: Optional[str] = None
    compatibility_state: str = "UNKNOWN"  # "SATISFIED", "VIOLATED", "UNKNOWN"
    accepted_sanitizers: list[str] = Field(default_factory=list)
    incompatible_sanitizers: list[str] = Field(default_factory=list)
    details: str = ""


class SecurityEvidenceChain(BaseModel):
    """Structured evidence chain linking a finding to its analysis provenance."""

    # Taint path evidence
    taint_source: Optional[TaintSourceEvidence] = None
    propagation_chain: list[PropagationStep] = Field(default_factory=list)
    sanitizer_evaluation: Optional[SanitizerEvidence] = None
    taint_sink: Optional[TaintSinkEvidence] = None

    # Contract evidence
    contract_evaluations: list[ContractEvaluationEvidence] = Field(default_factory=list)

    # Security boundary evidence
    boundary_evaluation: Optional[BoundaryEvaluationEvidence] = None

    # Path sensitivity evidence
    governing_path_conditions: list[str] = Field(default_factory=list)
    path_feasibility: str = "UNKNOWN"  # "FEASIBLE", "INFEASIBLE", "UNKNOWN"

    # Aggregate confidence and depth
    chain_confidence: str = "HIGH"  # "HIGH", "MEDIUM", "LOW"
    chain_depth: int = 0
    chain_hash: str = ""

    def compute_chain_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of the evidence chain content."""
        data = self.model_dump(mode="json", exclude={"chain_hash"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.chain_hash = digest
        return digest
