"""Strongly-typed Call Graph and Function Summary models for CodeSentinel Phase 15."""

from enum import Enum
from typing import Any, Optional
import uuid
from pydantic import BaseModel, Field

from analyzer.dataflow.taint.models import SinkCategory

# Namespace UUID for deterministic UUIDv5 generation
CALLGRAPH_NAMESPACE = uuid.UUID("a2b3c4d5-e6f7-4890-a1b2-c3d4e5f6a7b8")


class CallResolutionType(str, Enum):
    """Classification of call resolution."""
    RESOLVED_LOCAL = "RESOLVED_LOCAL"
    RESOLVED_IMPORT = "RESOLVED_IMPORT"
    UNRESOLVED = "UNRESOLVED"


class UnresolvedReason(str, Enum):
    """Reason for failing to resolve a call site."""
    EXTERNAL_MODULE = "EXTERNAL_MODULE"
    DYNAMIC_CALL = "DYNAMIC_CALL"
    MISSING_IMPORT = "MISSING_IMPORT"
    AMBIGUOUS = "AMBIGUOUS"
    OTHER = "OTHER"


class ParameterDef(BaseModel):
    """Definition of a function or method parameter."""
    name: str
    position: int
    has_default: bool = False
    default_value: Optional[str] = None
    type_hint: Optional[str] = None


class FunctionDefinition(BaseModel):
    """Static metadata for a discovered function, method, or arrow function."""
    id: str
    qualified_name: str
    file_path: str
    language: str
    name: str
    line_start: int
    line_end: int
    col_start: int = 0
    parameters: list[ParameterDef] = Field(default_factory=list)
    is_method: bool = False
    is_async: bool = False
    is_constructor: bool = False
    class_name: Optional[str] = None
    module_path: str = ""
    decorators: list[str] = Field(default_factory=list)

    @classmethod
    def create_deterministic_id(cls, file_path: str, qualified_name: str, line_start: int) -> str:
        """Generate a deterministic UUIDv5 from file path, qualified name, and start line."""
        norm_path = file_path.replace("\\", "/")
        seed = f"{norm_path}:{qualified_name}:{line_start}"
        return str(uuid.uuid5(CALLGRAPH_NAMESPACE, seed))


class CallEdge(BaseModel):
    """Directed call graph edge from caller to callee."""
    id: str
    caller_qualified_name: str
    callee_qualified_name: Optional[str] = None
    call_site_file: str
    call_site_line: int
    call_site_col: int = 0
    resolution_type: CallResolutionType
    argument_count: int = 0
    is_method_call: bool = False
    unresolved_reason: Optional[UnresolvedReason] = None
    callee_expression: Optional[str] = None

    @classmethod
    def create_deterministic_id(
        cls,
        caller_qn: str,
        callee_expr_or_qn: str,
        call_site_file: str,
        line: int,
        col: int,
    ) -> str:
        """Generate a deterministic UUIDv5 for a call edge."""
        norm_path = call_site_file.replace("\\", "/")
        seed = f"{caller_qn}->{callee_expr_or_qn}@{norm_path}:{line}:{col}"
        return str(uuid.uuid5(CALLGRAPH_NAMESPACE, seed))


class UnresolvedCall(BaseModel):
    """Details for a call expression that could not be statically resolved."""
    caller_qualified_name: str
    callee_expression: str
    call_site_file: str
    call_site_line: int
    call_site_col: int = 0
    reason: UnresolvedReason


class ResolutionStats(BaseModel):
    """Aggregate statistics for call resolution across the repository."""
    total_call_sites: int = 0
    resolved_local: int = 0
    resolved_import: int = 0
    unresolved: int = 0
    resolution_rate: float = 0.0


class CallGraph(BaseModel):
    """Repository-wide static call graph combining functions, edges, and statistics."""
    functions: dict[str, FunctionDefinition] = Field(default_factory=dict)
    edges: list[CallEdge] = Field(default_factory=list)
    unresolved_calls: list[UnresolvedCall] = Field(default_factory=list)
    resolution_stats: ResolutionStats = Field(default_factory=ResolutionStats)


class TaintTransfer(BaseModel):
    """Taint flow behavior from an input parameter through a function."""
    from_param_index: int
    to_return: bool = False
    to_sink_category: Optional[SinkCategory] = None
    via_operations: list[str] = Field(default_factory=list)
    sanitized_by: Optional[str] = None


class SummarySinkInvocation(BaseModel):
    """Record of a sensitive sink reachable within a function body from a parameter."""
    sink_id: str
    sink_category: SinkCategory
    receiving_param_index: int
    line: int
    is_parameterized: bool = False


class SummarySanitizerApplication(BaseModel):
    """Record of a sanitizer applied to a parameter within a function body."""
    sanitizer_id: str
    applied_to_param_index: int
    effective_categories: list[SinkCategory] = Field(default_factory=list)


class FunctionSummary(BaseModel):
    """Taint transfer specification for a single function scope."""
    qualified_name: str
    file_path: str
    parameters: list[ParameterDef] = Field(default_factory=list)
    taint_transfers: list[TaintTransfer] = Field(default_factory=list)
    sink_invocations: list[SummarySinkInvocation] = Field(default_factory=list)
    sanitizer_applications: list[SummarySanitizerApplication] = Field(default_factory=list)
    returns_tainted: bool = False
    is_identity: bool = False
    is_summarized: bool = True


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
