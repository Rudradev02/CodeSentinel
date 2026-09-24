"""Contextual function summarizer with branch refinement and multi-context lookup (Phase 16)."""

import ast
from typing import Any, Callable, Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.callgraph.context_manager import ConstantBranchEvaluator
from analyzer.dataflow.callgraph.models import (
    FunctionDefinition,
    FunctionSummary,
    RichSummaryTransfer,
    SummarySanitizerApplication,
    SummarySinkInvocation,
    TaintTransfer,
    TransferDirection,
)
from analyzer.dataflow.callgraph.summarizer import FunctionSummarizer
from analyzer.dataflow.types.models import CallContext, ConstantBool
from analyzer.dataflow.taint.models import SinkCategory, TaintSanitizer, TaintState
from analyzer.dataflow.taint.registry import TaintRegistry


class ContextualFunctionSummary(BaseModel):
    """Function summary specialized for a specific calling context and argument signature."""
    qualified_name: str
    context_id: str
    argument_taint_mask: list[bool] = Field(default_factory=list)
    constant_args: dict[int, str] = Field(default_factory=dict)
    taint_transfers: list[TaintTransfer] = Field(default_factory=list)
    sink_invocations: list[SummarySinkInvocation] = Field(default_factory=list)
    sanitizer_applications: list[SummarySanitizerApplication] = Field(default_factory=list)
    returns_tainted: bool = False
    is_widened: bool = False
    # Phase 17: Rich field-aware transfers
    rich_transfers: list[RichSummaryTransfer] = Field(default_factory=list)


class ContextSummaryManager:
    """Manages multi-context function summaries with deterministic lookup and widening."""

    def __init__(
        self,
        base_summaries: dict[str, FunctionSummary],
        registry: Optional[TaintRegistry] = None,
        max_summary_iterations: int = 5,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.base_summaries = base_summaries
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_summary_iterations = max_summary_iterations
        self.is_cancelled = is_cancelled
        # (qualified_name, context_id) -> ContextualFunctionSummary
        self.contextual_summaries: dict[tuple[str, str], ContextualFunctionSummary] = {}
        self.iteration_count: int = 0
        self.truncation_reasons: set[str] = set()

    def _find_sanitizer(self, language: str, callee_name: str) -> Optional[TaintSanitizer]:
        """Match a sanitizer across any category or well-known functions."""
        lang_upper = language.upper()
        c_name = callee_name.lower()
        for san in self.registry._sanitizers:
            if san.language.upper() == lang_upper:
                pat = san.callee_pattern.lower()
                if pat == c_name or c_name.endswith(f".{pat}") or pat.endswith(f".{c_name}"):
                    return san
        if c_name in ("escape", "html.escape", "sanitize", "shlex.quote", "int", "float", "dompurify.sanitize"):
            return TaintSanitizer(
                sanitizer_id="ESCAPE_FUNCTION",
                language=language,
                effective_categories=[SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE, SinkCategory.DOM_INJECTION],
                callee_pattern=callee_name,
                description="Sanitizer function",
                strength="CUSTOM",
            )
        return None

    def get_summary(
        self,
        qualified_name: str,
        context_id: Optional[str] = None,
    ) -> Optional[ContextualFunctionSummary | FunctionSummary]:
        """Deterministic lookup: exact context -> base summary -> None."""
        if context_id and (qualified_name, context_id) in self.contextual_summaries:
            return self.contextual_summaries[(qualified_name, context_id)]
        return self.base_summaries.get(qualified_name)

    def specialize_python_summary(
        self,
        fn_def: FunctionDefinition,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        context: CallContext,
    ) -> ContextualFunctionSummary:
        """Compute a specialized ContextualFunctionSummary under context and constant constraints."""
        key = (fn_def.qualified_name, context.context_id)
        if key in self.contextual_summaries:
            return self.contextual_summaries[key]

        param_names = [p.name for p in fn_def.parameters]
        param_states: dict[str, TaintState] = {}
        for idx, name in enumerate(param_names):
            if idx < len(context.argument_taint_mask) and context.argument_taint_mask[idx]:
                param_states[name] = TaintState.TAINTED
            else:
                param_states[name] = TaintState.UNTAINTED

        taint_transfers: list[TaintTransfer] = []
        sink_invocations: list[SummarySinkInvocation] = []
        sanitizer_apps: list[SummarySanitizerApplication] = []
        returns_tainted = False

        # Local tracking
        var_states: dict[str, TaintState] = dict(param_states)
        var_sanitizers: dict[str, list[str]] = {}

        field_transfers: list[RichSummaryTransfer] = []

        # Filter statements respecting constant conditions
        active_stmts = self._filter_active_statements(fn_node.body, param_names, context.constant_args)

        for stmt in active_stmts:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                val_node = stmt.value
                if val_node is None:
                    continue

                # Phase 17: Track field writes (self.f = p)
                assign_targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for t in assign_targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in ("self", "this"):
                        rhs_names = [n.id for n in ast.walk(val_node) if isinstance(n, ast.Name)]
                        for p_idx, p_name in enumerate(param_names):
                            if (p_name in rhs_names or any(var_states.get(n) == TaintState.TAINTED for n in rhs_names)) and var_states.get(p_name) == TaintState.TAINTED:
                                field_transfers.append(
                                    RichSummaryTransfer(
                                        direction=TransferDirection.PARAM_TO_FIELD,
                                        from_param_index=p_idx,
                                        to_field_name=t.attr,
                                        taint_state=TaintState.TAINTED,
                                    )
                                )

                targets = (
                    [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                    if isinstance(stmt, ast.Assign)
                    else ([stmt.target.id] if isinstance(stmt.target, ast.Name) else [])
                )
                if not targets:
                    continue
                target_var = targets[0]

                # Check if RHS applies a sanitizer
                is_sanitized = False
                if isinstance(val_node, ast.Call):
                    callee_name = getattr(val_node.func, "id", getattr(val_node.func, "attr", ""))
                    matched_san = self._find_sanitizer("PYTHON", callee_name)
                    if matched_san:
                        is_sanitized = True
                        var_states[target_var] = TaintState.SANITIZED
                        var_sanitizers[target_var] = [matched_san.sanitizer_id]
                        sanitizer_apps.append(
                            SummarySanitizerApplication(
                                sanitizer_id=matched_san.sanitizer_id,
                                applied_to_param_index=0,
                                effective_categories=matched_san.effective_categories,
                            )
                        )

                if not is_sanitized:
                    names = [n.id for n in ast.walk(val_node) if isinstance(n, ast.Name)]
                    tainted = any(var_states.get(n) == TaintState.TAINTED for n in names)
                    if tainted:
                        var_states[target_var] = TaintState.TAINTED
                        var_sanitizers[target_var] = []
                    else:
                        var_states[target_var] = TaintState.UNTAINTED

            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                callee_name = getattr(call.func, "id", getattr(call.func, "attr", ""))
                receiver_name = getattr(call.func.value, "id", None) if isinstance(call.func, ast.Attribute) else None
                matched_sink = self.registry.find_matching_sink("PYTHON", callee_name, receiver_name)
                if matched_sink:
                    for v_idx in matched_sink.vulnerable_arg_indices:
                        if v_idx < len(call.args):
                            arg_names = [n.id for n in ast.walk(call.args[v_idx]) if isinstance(n, ast.Name)]
                            for p_idx, p_name in enumerate(param_names):
                                if p_name in arg_names and var_states.get(p_name) == TaintState.TAINTED:
                                    sink_invocations.append(
                                        SummarySinkInvocation(
                                            sink_id=matched_sink.sink_id,
                                            sink_category=matched_sink.category,
                                            receiving_param_index=p_idx,
                                            line=call.lineno,
                                        )
                                    )

            elif isinstance(stmt, ast.Return) and stmt.value:
                # Phase 17: Track field returns (return self.f)
                if isinstance(stmt.value, ast.Attribute) and isinstance(stmt.value.value, ast.Name) and stmt.value.value.id in ("self", "this"):
                    field_transfers.append(
                        RichSummaryTransfer(
                            direction=TransferDirection.FIELD_TO_RETURN,
                            from_field_name=stmt.value.attr,
                            taint_state=TaintState.TAINTED,
                        )
                    )

                ret_san: Optional[str] = None
                if isinstance(stmt.value, ast.Call):
                    callee_name = getattr(stmt.value.func, "id", getattr(stmt.value.func, "attr", ""))
                    matched_san = self._find_sanitizer("PYTHON", callee_name)
                    if matched_san:
                        ret_san = matched_san.sanitizer_id
                        sanitizer_apps.append(
                            SummarySanitizerApplication(
                                sanitizer_id=matched_san.sanitizer_id,
                                applied_to_param_index=0,
                                effective_categories=matched_san.effective_categories,
                            )
                        )

                names = [n.id for n in ast.walk(stmt.value) if isinstance(n, ast.Name)]
                for p_idx, p_name in enumerate(param_names):
                    if any(n == p_name or var_states.get(n) == TaintState.TAINTED for n in names):
                        if var_states.get(p_name) == TaintState.TAINTED:
                            san = ret_san or (var_sanitizers.get(p_name, [None])[0] if var_sanitizers.get(p_name) else None)
                            if not san:
                                returns_tainted = True
                            taint_transfers.append(
                                TaintTransfer(
                                    from_param_index=p_idx,
                                    to_return=True,
                                    sanitized_by=san,
                                )
                            )

        const_str_dict = {k: v.value for k, v in context.constant_args.items()}

        # Phase 17: Rich summary transfers
        rich_transfers: list[RichSummaryTransfer] = []
        for tr in taint_transfers:
            if tr.to_return:
                rich_transfers.append(
                    RichSummaryTransfer(
                        direction=TransferDirection.PARAM_TO_RETURN,
                        from_param_index=tr.from_param_index,
                        taint_state=TaintState.TAINTED,
                        sanitized_by=tr.sanitized_by,
                    )
                )
        for sk in sink_invocations:
            rich_transfers.append(
                RichSummaryTransfer(
                    direction=TransferDirection.PARAM_TO_SINK,
                    from_param_index=sk.receiving_param_index,
                    to_sink_category=sk.sink_category,
                    taint_state=TaintState.TAINTED,
                )
            )
        rich_transfers.extend(field_transfers)

        summary = ContextualFunctionSummary(
            qualified_name=fn_def.qualified_name,
            context_id=context.context_id,
            argument_taint_mask=context.argument_taint_mask,
            constant_args=const_str_dict,
            taint_transfers=taint_transfers,
            sink_invocations=sink_invocations,
            sanitizer_applications=sanitizer_apps,
            returns_tainted=returns_tainted,
            rich_transfers=rich_transfers,
        )
        self.contextual_summaries[key] = summary
        return summary

    def _filter_active_statements(
        self,
        stmts: list[ast.stmt],
        param_names: list[str],
        constant_args: dict[int, ConstantBool],
    ) -> list[ast.stmt]:
        """Prune unreachable branches based on literal boolean constant args."""
        active: list[ast.stmt] = []
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                cond_val = ConstantBranchEvaluator.evaluate_python_condition(
                    stmt.test, param_names, constant_args
                )
                if cond_val == ConstantBool.TRUE:
                    active.extend(self._filter_active_statements(stmt.body, param_names, constant_args))
                elif cond_val == ConstantBool.FALSE:
                    active.extend(self._filter_active_statements(stmt.orelse, param_names, constant_args))
                else:
                    active.extend(self._filter_active_statements(stmt.body, param_names, constant_args))
                    active.extend(self._filter_active_statements(stmt.orelse, param_names, constant_args))
            else:
                active.append(stmt)
        return active
