"""Strongly-typed taint analysis models and schemas for CodeSentinel."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from analyzer.models.findings import FindingConfidence, FindingSeverity


class SourceCategory(str, Enum):
    """Classification of untrusted input source."""
    HTTP_PARAM = "HTTP_PARAM"
    HTTP_BODY = "HTTP_BODY"
    HTTP_HEADER = "HTTP_HEADER"
    COOKIE = "COOKIE"
    ENV_VAR = "ENV_VAR"
    CLI_INPUT = "CLI_INPUT"
    DOM_INPUT = "DOM_INPUT"


class SinkCategory(str, Enum):
    """Classification of sensitive sink operations."""
    SQL_EXECUTE = "SQL_EXECUTE"
    COMMAND_EXECUTE = "COMMAND_EXECUTE"
    CODE_EVAL = "CODE_EVAL"
    DOM_INJECTION = "DOM_INJECTION"
    FILE_PATH = "FILE_PATH"


class TaintState(str, Enum):
    """Discrete state of taint carried by a symbol or expression."""
    UNTAINTED = "UNTAINTED"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def merge(cls, state1: "TaintState", state2: "TaintState") -> "TaintState":
        """Conservative join lattice merge:
        TAINTED | any = TAINTED
        UNKNOWN | UNTAINTED = UNKNOWN
        SANITIZED | UNTAINTED = SANITIZED
        SANITIZED | UNKNOWN = UNKNOWN
        """
        if state1 == cls.TAINTED or state2 == cls.TAINTED:
            return cls.TAINTED
        if state1 == cls.UNKNOWN or state2 == cls.UNKNOWN:
            return cls.UNKNOWN
        if state1 == cls.SANITIZED or state2 == cls.SANITIZED:
            return cls.SANITIZED
        return cls.UNTAINTED


class TaintSource(BaseModel):
    """Declaration of an untrusted input vector."""
    source_id: str
    language: str
    category: SourceCategory
    framework: Optional[str] = None
    pattern_type: str  # "ATTRIBUTE", "SUBSCRIPT", "CALL"
    base_object: str   # e.g. "request", "location", "document"
    member: str        # e.g. "args", "GET", "search"
    description: str


class TaintSink(BaseModel):
    """Declaration of a sensitive sink function or attribute."""
    sink_id: str
    language: str
    category: SinkCategory
    rule_id: str
    callee_name: str                        # e.g. "execute", "run", "innerHTML"
    module_or_object: Optional[str] = None  # e.g. "subprocess", "cursor"
    vulnerable_arg_indices: list[int] = Field(default_factory=lambda: [0])
    supports_parameter_binding: bool = False
    parameter_binding_arg_index: Optional[int] = None  # e.g. 1 in cursor.execute(query, params)
    description: str
    severity: FindingSeverity = FindingSeverity.HIGH
    confidence: FindingConfidence = FindingConfidence.HIGH


class TaintSanitizer(BaseModel):
    """Declaration of a context-specific sanitizer function."""
    sanitizer_id: str
    language: str
    effective_categories: list[SinkCategory]
    callee_pattern: str       # e.g. "int", "shlex.quote", "DOMPurify.sanitize"
    description: str
    strength: str             # "NUMERIC_CONSTRAINT", "SHELL_ESCAPE", "HTML_STRIP"


class TaintStep(BaseModel):
    """A single step in a taint propagation trace."""
    step: int
    line: int
    column: int
    operation: str  # "SOURCE", "ASSIGNMENT", "CALL", "SANITIZER", "SINK"
    from_symbol: Optional[str] = None
    to_symbol: Optional[str] = None
    expression: str
    state: TaintState = TaintState.TAINTED


class TaintPath(BaseModel):
    """End-to-end evidence trace connecting untrusted source to sensitive sink."""
    flow_type: str = "INTRA_PROCEDURAL_TAINT"
    source: dict[str, Any]
    propagation: list[dict[str, Any]] = Field(default_factory=list)
    sanitizer: Optional[dict[str, Any]] = None
    sink: dict[str, Any]
    path_summary: str
    category: SinkCategory


class CallChainStep(BaseModel):
    """One invocation step in an interprocedural taint flow."""
    caller_function: str
    callee_function: str
    caller_file: str
    callee_file: str
    call_site_line: int
    call_site_col: int
    argument_index: int
    callee_param_name: str
    taint_action: str  # "PROPAGATE_THROUGH" | "REACHES_SINK" | "SANITIZED"
    path_condition: Optional[str] = None
    branch_taken: Optional[str] = None
    guard_predicate: Optional[str] = None
    path_status: Optional[str] = None
    # Phase 19: Interprocedural contract evidence
    contract_status: Optional[str] = None
    contract_effect: Optional[str] = None
    precondition_kind: Optional[str] = None
    contract_id: Optional[str] = None



class InterproceduralTaintPath(BaseModel):
    """End-to-end multi-function evidence trace connecting source to sink."""
    flow_type: str = "INTER_PROCEDURAL_TAINT"
    source: dict[str, Any]
    call_chain: list[CallChainStep] = Field(default_factory=list)
    sanitizer: Optional[dict[str, Any]] = None
    sink: dict[str, Any]
    path_summary: str
    category: SinkCategory
    total_depth: int = 1
    files_involved: list[str] = Field(default_factory=list)

