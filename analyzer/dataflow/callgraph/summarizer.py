"""Function summary generation computing parameter taint transfers, sinks, and sanitizers."""

import ast
from typing import Any, Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.callgraph.models import (
    CallGraph,
    FunctionDefinition,
    FunctionSummary,
    ParameterDef,
    SummarySanitizerApplication,
    SummarySinkInvocation,
    TaintTransfer,
)
from analyzer.dataflow.callgraph.resolver import CallResolver
from analyzer.dataflow.js_visitor import JSDataFlowAnalyzer
from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.dataflow.symbol import DefinitionKind, Scope, ScopeKind
from analyzer.dataflow.taint.models import SinkCategory, TaintPath, TaintSanitizer, TaintSink, TaintState, TaintStep
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry
from analyzer.models.parse import ParsedFile
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class _PythonSummaryVisitor(PythonDataFlowAnalyzer):
    """Subclass of PythonDataFlowAnalyzer customized for function summary evaluation."""

    def __init__(
        self,
        registry: TaintRegistry,
        param_index: int,
        param_name: str,
        known_summaries: Optional[dict[str, FunctionSummary]] = None,
        resolver: Optional[CallResolver] = None,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(
            registry=registry,
            max_depth=25,
            max_symbols=100,
            max_statements=max_statements,
            is_cancelled=is_cancelled,
        )
        self.param_index = param_index
        self.param_name = param_name
        self.known_summaries = known_summaries or {}
        self.resolver = resolver
        self.detected_sinks: list[SummarySinkInvocation] = []
        self.detected_sanitizers: list[SummarySanitizerApplication] = []
        self.transfers: list[TaintTransfer] = []
        self.is_identity_candidate: bool = False
        self.has_non_identity_return: bool = False

    def _process_statements(
        self,
        statements: list[ast.stmt],
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str] = None,
        statement_counter: Optional[list[int]] = None,
    ) -> None:
        """Process statement sequence including Return statements."""
        if statement_counter is None:
            statement_counter = [0]

        for stmt in statements:
            statement_counter[0] += 1
            if statement_counter[0] % 25 == 0:
                propagator.check_cancellation()

            if isinstance(stmt, ast.Assign):
                self._handle_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.AnnAssign):
                self._handle_ann_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.AugAssign):
                self._handle_aug_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.Expr):
                self._handle_expr_stmt(stmt, propagator, fn_scope, file_path, target_rule_id)
            elif isinstance(stmt, ast.If):
                self._handle_if_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            elif isinstance(stmt, (ast.For, ast.While)):
                self._handle_loop_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            elif isinstance(stmt, ast.Try):
                self._handle_try_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            elif isinstance(stmt, ast.Return):
                self._handle_return_stmt(stmt, propagator, fn_scope, file_path)

    def _propagate_rhs_to_target(
        self,
        rhs_node: ast.AST,
        target_symbol: str,
        propagator: TaintPropagator,
        line: int,
        col: int,
        raw_rhs: str,
    ) -> None:
        """Propagate RHS to target with callee summary awareness."""
        # Check if RHS is a call to a function with a known summary
        if isinstance(rhs_node, ast.Call):
            callee_name = self._extract_callee_name(rhs_node)
            arg_names = [name for arg in rhs_node.args for name in self._extract_names(arg)]

            # 1. First check if it's a known sanitizer
            for cat in [SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE]:
                san = self.registry.find_matching_sanitizer("PYTHON", callee_name, cat)
                if san:
                    # Record sanitizer application if input was tainted
                    tainted_args = [s for s in arg_names if propagator.symbol_states.get(s) in (TaintState.TAINTED, TaintState.SANITIZED)]
                    if tainted_args:
                        self.detected_sanitizers.append(
                            SummarySanitizerApplication(
                                sanitizer_id=san.sanitizer_id,
                                applied_to_param_index=self.param_index,
                                effective_categories=list(san.effective_categories),
                            )
                        )
                    super()._propagate_rhs_to_target(rhs_node, target_symbol, propagator, line, col, raw_rhs)
                    return

            # 2. Check if callee has a FunctionSummary in known_summaries
            callee_summary = self._lookup_summary(callee_name)
            if callee_summary:
                self._apply_callee_summary(
                    callee_summary=callee_summary,
                    call_node=rhs_node,
                    target_symbol=target_symbol,
                    propagator=propagator,
                    line=line,
                    col=col,
                    raw_rhs=raw_rhs,
                )
                return

        # Fallback to base analyzer logic
        super()._propagate_rhs_to_target(rhs_node, target_symbol, propagator, line, col, raw_rhs)

    def _lookup_summary(self, callee_name: str) -> Optional[FunctionSummary]:
        """Look up function summary by name or qualified name."""
        if not callee_name or not self.known_summaries:
            return None
        # Try direct qualified name match
        if callee_name in self.known_summaries:
            return self.known_summaries[callee_name]
        # Try suffix / function name match
        for qn, s in self.known_summaries.items():
            if qn.endswith(f".{callee_name}") or qn == callee_name:
                return s
        return None

    def _apply_callee_summary(
        self,
        callee_summary: FunctionSummary,
        call_node: ast.Call,
        target_symbol: Optional[str],
        propagator: TaintPropagator,
        line: int,
        col: int,
        raw_rhs: str,
    ) -> None:
        """Apply callee summary to transfer taint and record downstream sinks."""
        transferred_to_return = False
        sanitized_by_callee: Optional[str] = None

        for arg_idx, arg_node in enumerate(call_node.args):
            arg_names = self._extract_names(arg_node)
            is_arg_tainted = any(
                propagator.symbol_states.get(sym) == TaintState.TAINTED for sym in arg_names
            )
            if not is_arg_tainted:
                continue

            # Check callee taint transfers
            for transfer in callee_summary.taint_transfers:
                if transfer.from_param_index == arg_idx:
                    if transfer.to_return:
                        transferred_to_return = True
                        if transfer.sanitized_by:
                            sanitized_by_callee = transfer.sanitized_by

            # Check callee sink invocations
            for sink_inv in callee_summary.sink_invocations:
                if sink_inv.receiving_param_index == arg_idx:
                    self.detected_sinks.append(
                        SummarySinkInvocation(
                            sink_id=sink_inv.sink_id,
                            sink_category=sink_inv.sink_category,
                            receiving_param_index=self.param_index,
                            line=line,
                            is_parameterized=sink_inv.is_parameterized,
                        )
                    )

        if target_symbol:
            if transferred_to_return:
                propagator.step_counter += 1
                step = TaintStep(
                    step=propagator.step_counter,
                    line=line,
                    column=col,
                    operation="CALLEE_PROPAGATION",
                    from_symbol=self.param_name,
                    to_symbol=target_symbol,
                    expression=raw_rhs,
                    state=TaintState.SANITIZED if sanitized_by_callee else TaintState.TAINTED,
                )
                propagator.symbol_states[target_symbol] = TaintState.SANITIZED if sanitized_by_callee else TaintState.TAINTED
                propagator.symbol_traces[target_symbol] = [step]
            else:
                propagator.symbol_states[target_symbol] = TaintState.UNTAINTED

    def _check_call_for_sink(
        self,
        call_node: ast.Call,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> Optional[TaintPath]:
        """Check call for sink and record SummarySinkInvocation."""
        path = super()._check_call_for_sink(call_node, propagator, fn_scope, file_path, target_rule_id)
        if path:
            cat = path.category
            self.detected_sinks.append(
                SummarySinkInvocation(
                    sink_id=path.sink.get("sink_id", cat.value if hasattr(cat, "value") else str(cat)),
                    sink_category=cat,
                    receiving_param_index=self.param_index,
                    line=path.sink.get("line", call_node.lineno),
                    is_parameterized=False,
                )
            )
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_sink_category=cat,
                    via_operations=["SINK_INVOCATION"],
                )
            )
        return path

    def _handle_return_stmt(
        self,
        stmt: ast.Return,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
    ) -> None:
        """Analyze whether the returned expression propagates taint from self.param_index."""
        if stmt.value is None:
            return

        raw_return = ast.unparse(stmt.value) if hasattr(ast, "unparse") else "<return>"

        # 1. Direct call in return
        if isinstance(stmt.value, ast.Call):
            # Check if it calls a sink
            self._check_call_for_sink(stmt.value, propagator, fn_scope, file_path)

            callee_name = self._extract_callee_name(stmt.value)
            arg_names = [name for arg in stmt.value.args for name in self._extract_names(arg)]
            tainted_args = [s for s in arg_names if propagator.symbol_states.get(s) == TaintState.TAINTED]

            # Check if it's a sanitizer
            for cat in [SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE]:
                san = self.registry.find_matching_sanitizer("PYTHON", callee_name, cat)
                if san and tainted_args:
                    self.detected_sanitizers.append(
                        SummarySanitizerApplication(
                            sanitizer_id=san.sanitizer_id,
                            applied_to_param_index=self.param_index,
                            effective_categories=list(san.effective_categories),
                        )
                    )
                    self.transfers.append(
                        TaintTransfer(
                            from_param_index=self.param_index,
                            to_return=True,
                            sanitized_by=san.sanitizer_id,
                            via_operations=["SANITIZER"],
                        )
                    )
                    return

            # Check callee summary
            callee_summary = self._lookup_summary(callee_name)
            if callee_summary:
                self._apply_callee_summary(callee_summary, stmt.value, None, propagator, stmt.lineno, stmt.col_offset, raw_return)
                for arg_idx, arg_node in enumerate(stmt.value.args):
                    if any(propagator.symbol_states.get(n) == TaintState.TAINTED for n in self._extract_names(arg_node)):
                        for tr in callee_summary.taint_transfers:
                            if tr.from_param_index == arg_idx and tr.to_return:
                                self.transfers.append(
                                    TaintTransfer(
                                        from_param_index=self.param_index,
                                        to_return=True,
                                        via_operations=["CALLEE_CALL"] + tr.via_operations,
                                        sanitized_by=tr.sanitized_by,
                                    )
                                )
                                return

            # Unknown function call preserves taint
            if tainted_args:
                self.transfers.append(
                    TaintTransfer(
                        from_param_index=self.param_index,
                        to_return=True,
                        via_operations=["UNKNOWN_TRANSFORMATION"],
                    )
                )
                return

        # 2. Direct identifier return: return x
        if isinstance(stmt.value, ast.Name):
            ret_sym = stmt.value.id
            state = propagator.symbol_states.get(ret_sym, TaintState.UNTAINTED)
            if state == TaintState.TAINTED:
                trace = propagator.symbol_traces.get(ret_sym, [])
                ops = [step.operation for step in trace if step.operation]
                self.transfers.append(
                    TaintTransfer(
                        from_param_index=self.param_index,
                        to_return=True,
                        via_operations=ops or ["RETURN"],
                    )
                )
                if ret_sym == self.param_name and len(trace) <= 1:
                    self.is_identity_candidate = True
                else:
                    self.has_non_identity_return = True
                return
            elif state == TaintState.SANITIZED:
                sans = propagator.symbol_sanitizers.get(ret_sym, [])
                san_id = sans[0].sanitizer_id if sans else "SANITIZED"
                self.transfers.append(
                    TaintTransfer(
                        from_param_index=self.param_index,
                        to_return=True,
                        sanitized_by=san_id,
                        via_operations=["SANITIZER"],
                    )
                )
                return

        # 3. Formatted strings (f-strings) or binary concatenation
        if isinstance(stmt.value, (ast.JoinedStr, ast.BinOp)):
            names = self._extract_names(stmt.value)
            tainted_names = [n for n in names if propagator.symbol_states.get(n) == TaintState.TAINTED]
            if tainted_names:
                op_name = "FORMAT_STRING" if isinstance(stmt.value, ast.JoinedStr) else "CONCATENATION"
                self.transfers.append(
                    TaintTransfer(
                        from_param_index=self.param_index,
                        to_return=True,
                        via_operations=[op_name],
                    )
                )
                self.has_non_identity_return = True
                return

        # 4. Container or expression referencing symbols
        names = self._extract_names(stmt.value)
        if any(propagator.symbol_states.get(n) == TaintState.TAINTED for n in names):
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_return=True,
                    via_operations=["ASSIGNMENT"],
                )
            )
            self.has_non_identity_return = True


class _JSSummaryVisitor(JSDataFlowAnalyzer):
    """Subclass of JSDataFlowAnalyzer customized for function summary evaluation."""

    def __init__(
        self,
        registry: TaintRegistry,
        param_index: int,
        param_name: str,
        known_summaries: Optional[dict[str, FunctionSummary]] = None,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(
            registry=registry,
            max_depth=25,
            max_symbols=100,
            max_statements=max_statements,
            is_cancelled=is_cancelled,
        )
        self.param_index = param_index
        self.param_name = param_name
        self.known_summaries = known_summaries or {}
        self.detected_sinks: list[SummarySinkInvocation] = []
        self.detected_sanitizers: list[SummarySanitizerApplication] = []
        self.transfers: list[TaintTransfer] = []
        self.is_identity_candidate: bool = False
        self.has_non_identity_return: bool = False

    def _process_statements(
        self,
        statements: list[Node],
        propagator: TaintPropagator,
        fn_scope: Scope,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Process JS statements including return_statement."""
        stmt_count = 0
        for stmt in statements:
            stmt_count += 1
            if stmt_count % 25 == 0:
                propagator.check_cancellation()

            if stmt.type in ("lexical_declaration", "variable_declaration"):
                for child in stmt.children:
                    if child.type == "variable_declarator":
                        self._handle_declarator(child, propagator, fn_scope, source_bytes, file_path)
            elif stmt.type == "expression_statement":
                for child in stmt.children:
                    if child.type == "assignment_expression":
                        self._handle_assignment_expr(child, propagator, fn_scope, source_bytes, file_path, target_rule_id)
                    elif child.type == "call_expression":
                        self._handle_call_expr(child, propagator, source_bytes, file_path, target_rule_id)
            elif stmt.type == "return_statement":
                self._handle_return_statement(stmt, propagator, source_bytes, file_path)

    def _handle_call_expr(
        self,
        call_node: Node,
        propagator: TaintPropagator,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> Optional[TaintPath]:
        """Check call for sink and record SummarySinkInvocation."""
        path = super()._handle_call_expr(call_node, propagator, source_bytes, file_path, target_rule_id)
        if path:
            cat = path.category
            line, _, _, _ = get_node_line_and_col(call_node)
            self.detected_sinks.append(
                SummarySinkInvocation(
                    sink_id=path.sink.get("sink_id", cat.value if hasattr(cat, "value") else str(cat)),
                    sink_category=cat,
                    receiving_param_index=self.param_index,
                    line=line,
                    is_parameterized=False,
                )
            )
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_sink_category=cat,
                    via_operations=["SINK_INVOCATION"],
                )
            )
        return path

    def _handle_return_statement(
        self,
        return_node: Node,
        propagator: TaintPropagator,
        source_bytes: bytes,
        file_path: str,
    ) -> None:
        """Analyze JS return statement."""
        raw_text = node_text(return_node, source_bytes).strip()
        names = self._extract_identifier_names(return_node, source_bytes)

        # Check if direct identifier return
        # e.g. "return x;"
        clean_ret = raw_text.removeprefix("return").removesuffix(";").strip()
        if clean_ret == self.param_name and propagator.symbol_states.get(self.param_name) == TaintState.TAINTED:
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_return=True,
                    via_operations=["RETURN"],
                )
            )
            self.is_identity_candidate = True
            return

        tainted_names = [n for n in names if propagator.symbol_states.get(n) == TaintState.TAINTED]
        sanitized_names = [n for n in names if propagator.symbol_states.get(n) == TaintState.SANITIZED]

        if tainted_names:
            op = "CONCATENATION" if "+" in raw_text or "`" in raw_text else "ASSIGNMENT"
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_return=True,
                    via_operations=[op],
                )
            )
            self.has_non_identity_return = True
        elif sanitized_names:
            sans = propagator.symbol_sanitizers.get(sanitized_names[0], [])
            san_id = sans[0].sanitizer_id if sans else "SANITIZED"
            self.transfers.append(
                TaintTransfer(
                    from_param_index=self.param_index,
                    to_return=True,
                    sanitized_by=san_id,
                    via_operations=["SANITIZER"],
                )
            )


class FunctionSummarizer:
    """Generates FunctionSummary models via parameter-seeded intraprocedural taint analysis."""

    def __init__(
        self,
        registry: Optional[TaintRegistry] = None,
        max_summary_iterations: int = 3,
        max_function_body_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_summary_iterations = max_summary_iterations
        self.max_function_body_statements = max_function_body_statements
        self.is_cancelled = is_cancelled

    def check_cancellation(self) -> None:
        """Cooperative cancellation checkpoint."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Function summarization was cancelled by user")

    def summarize_function(
        self,
        fn_def: FunctionDefinition,
        tree_or_node: Any,
        content: str | bytes,
        known_summaries: Optional[dict[str, FunctionSummary]] = None,
        resolver: Optional[CallResolver] = None,
    ) -> FunctionSummary:
        """Generate a FunctionSummary for a single function definition."""
        self.check_cancellation()

        lang = fn_def.language.upper()
        if lang == "PYTHON":
            return self._summarize_python_function(
                fn_def=fn_def,
                tree=tree_or_node,
                file_content=content if isinstance(content, str) else content.decode("utf-8", errors="replace"),
                known_summaries=known_summaries,
                resolver=resolver,
            )
        elif lang in ("JAVASCRIPT", "TYPESCRIPT"):
            return self._summarize_jsts_function(
                fn_def=fn_def,
                root_node=tree_or_node,
                source_bytes=content.encode("utf-8") if isinstance(content, str) else content,
                known_summaries=known_summaries,
            )
        else:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=False,
            )

    def _summarize_python_function(
        self,
        fn_def: FunctionDefinition,
        tree: ast.AST,
        file_content: str,
        known_summaries: Optional[dict[str, FunctionSummary]] = None,
        resolver: Optional[CallResolver] = None,
    ) -> FunctionSummary:
        """Generate summary for a Python function."""
        # Find matching function node
        fn_node: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None
        if isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)) and tree.name == fn_def.name:
            fn_node = tree
        else:
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == fn_def.name
                    and getattr(node, "lineno", 0) == fn_def.line_start
                ):
                    fn_node = node
                    break

        if not fn_node:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=False,
            )

        # Enforce max statements bound
        if len(fn_node.body) > self.max_function_body_statements:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=False,
            )

        all_transfers: list[TaintTransfer] = []
        all_sinks: list[SummarySinkInvocation] = []
        all_sanitizers: list[SummarySanitizerApplication] = []
        is_identity = False

        # If function has no parameters, evaluate for direct returns/sinks
        if not fn_def.parameters:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=[],
                returns_tainted=False,
                is_identity=False,
                is_summarized=True,
            )

        # Seed each parameter individually
        for p_idx, param in enumerate(fn_def.parameters):
            self.check_cancellation()

            visitor = _PythonSummaryVisitor(
                registry=self.registry,
                param_index=p_idx,
                param_name=param.name,
                known_summaries=known_summaries,
                resolver=resolver,
                max_statements=self.max_function_body_statements,
                is_cancelled=self.is_cancelled,
            )

            propagator = TaintPropagator(
                registry=self.registry,
                max_depth=25,
                max_symbols=100,
                max_statements=self.max_function_body_statements,
                is_cancelled=self.is_cancelled,
            )

            fn_scope = Scope(
                id=Scope.create_deterministic_id(
                    fn_def.file_path,
                    ScopeKind.FUNCTION,
                    fn_def.name,
                    fn_def.line_start,
                    fn_def.col_start,
                ),
                name=fn_def.name,
                qualified_name=fn_def.qualified_name,
                kind=ScopeKind.FUNCTION,
                line_start=fn_def.line_start,
                line_end=fn_def.line_end,
                col_start=fn_def.col_start,
            )

            # Register parameters, seeding current parameter as TAINTED
            for idx, p in enumerate(fn_def.parameters):
                fn_scope.add_definition(
                    symbol_name=p.name,
                    kind=DefinitionKind.PARAMETER,
                    line=fn_def.line_start,
                    col=fn_def.col_start,
                )
                propagator.register_parameter(p.name, is_tainted=(idx == p_idx))

            # Process statements
            statements = fn_node.body[: self.max_function_body_statements]
            visitor._process_statements(
                statements=statements,
                propagator=propagator,
                fn_scope=fn_scope,
                file_path=fn_def.file_path,
            )

            # Check identity for first parameter
            if p_idx == 0 and visitor.is_identity_candidate and not visitor.has_non_identity_return:
                is_identity = True

            all_transfers.extend(visitor.transfers)
            all_sinks.extend(visitor.detected_sinks)
            all_sanitizers.extend(visitor.detected_sanitizers)

        returns_tainted = any(tr.to_return and not tr.sanitized_by for tr in all_transfers)

        return FunctionSummary(
            qualified_name=fn_def.qualified_name,
            file_path=fn_def.file_path,
            parameters=fn_def.parameters,
            taint_transfers=all_transfers,
            sink_invocations=all_sinks,
            sanitizer_applications=all_sanitizers,
            returns_tainted=returns_tainted,
            is_identity=is_identity,
            is_summarized=True,
        )

    def _summarize_jsts_function(
        self,
        fn_def: FunctionDefinition,
        root_node: Node,
        source_bytes: bytes,
        known_summaries: Optional[dict[str, FunctionSummary]] = None,
    ) -> FunctionSummary:
        """Generate summary for a JS/TS function."""
        # Locate function node
        analyzer = JSDataFlowAnalyzer(registry=self.registry)
        fn_nodes = analyzer._find_functions(root_node)
        target_fn_node: Optional[Node] = None

        for fn_node in fn_nodes:
            line_start, _, col_start, _ = get_node_line_and_col(fn_node)
            if line_start == fn_def.line_start:
                target_fn_node = fn_node
                break

        if not target_fn_node:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=False,
            )

        # Locate body
        body_node = target_fn_node.child_by_field_name("body")
        is_expression_body = False
        if not body_node:
            for child in target_fn_node.children:
                if child.type in ("statement_block", "expression_statement"):
                    body_node = child
                    break
                elif child.type in ("binary_expression", "template_string", "identifier", "call_expression"):
                    body_node = child
                    is_expression_body = True
                    break

        if not body_node:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=True,
            )

        statements = [c for c in body_node.children if not c.type.startswith("comment")][: self.max_function_body_statements]
        if len(statements) > self.max_function_body_statements:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=fn_def.parameters,
                is_summarized=False,
            )

        all_transfers: list[TaintTransfer] = []
        all_sinks: list[SummarySinkInvocation] = []
        all_sanitizers: list[SummarySanitizerApplication] = []
        is_identity = False

        if not fn_def.parameters:
            return FunctionSummary(
                qualified_name=fn_def.qualified_name,
                file_path=fn_def.file_path,
                parameters=[],
                returns_tainted=False,
                is_identity=False,
                is_summarized=True,
            )

        for p_idx, param in enumerate(fn_def.parameters):
            self.check_cancellation()

            visitor = _JSSummaryVisitor(
                registry=self.registry,
                param_index=p_idx,
                param_name=param.name,
                known_summaries=known_summaries,
                max_statements=self.max_function_body_statements,
                is_cancelled=self.is_cancelled,
            )

            propagator = TaintPropagator(
                registry=self.registry,
                max_depth=25,
                max_symbols=100,
                max_statements=self.max_function_body_statements,
                is_cancelled=self.is_cancelled,
            )

            fn_scope = Scope(
                id=Scope.create_deterministic_id(
                    fn_def.file_path,
                    ScopeKind.FUNCTION,
                    fn_def.name,
                    fn_def.line_start,
                    fn_def.col_start,
                ),
                name=fn_def.name,
                qualified_name=fn_def.qualified_name,
                kind=ScopeKind.FUNCTION,
                line_start=fn_def.line_start,
                line_end=fn_def.line_end,
                col_start=fn_def.col_start,
            )

            for idx, p in enumerate(fn_def.parameters):
                fn_scope.add_definition(
                    symbol_name=p.name,
                    kind=DefinitionKind.PARAMETER,
                    line=fn_def.line_start,
                    col=fn_def.col_start,
                )
                propagator.register_parameter(p.name, is_tainted=(idx == p_idx))

            if is_expression_body:
                # Direct expression body arrow function: (x) => x or (x) => "SELECT " + x
                expr_text = node_text(body_node, source_bytes).strip()
                if expr_text == param.name:
                    visitor.transfers.append(
                        TaintTransfer(
                            from_param_index=p_idx,
                            to_return=True,
                            via_operations=["RETURN"],
                        )
                    )
                    if p_idx == 0:
                        visitor.is_identity_candidate = True
                elif param.name in expr_text:
                    visitor.transfers.append(
                        TaintTransfer(
                            from_param_index=p_idx,
                            to_return=True,
                            via_operations=["CONCATENATION"],
                        )
                    )
                    visitor.has_non_identity_return = True
            else:
                visitor._process_statements(
                    statements=statements,
                    propagator=propagator,
                    fn_scope=fn_scope,
                    source_bytes=source_bytes,
                    file_path=fn_def.file_path,
                )

            if p_idx == 0 and visitor.is_identity_candidate and not visitor.has_non_identity_return:
                is_identity = True

            all_transfers.extend(visitor.transfers)
            all_sinks.extend(visitor.detected_sinks)
            all_sanitizers.extend(visitor.detected_sanitizers)

        returns_tainted = any(tr.to_return and not tr.sanitized_by for tr in all_transfers)

        return FunctionSummary(
            qualified_name=fn_def.qualified_name,
            file_path=fn_def.file_path,
            parameters=fn_def.parameters,
            taint_transfers=all_transfers,
            sink_invocations=all_sinks,
            sanitizer_applications=all_sanitizers,
            returns_tainted=returns_tainted,
            is_identity=is_identity,
            is_summarized=True,
        )

    def summarize_all(
        self,
        functions: list[FunctionDefinition],
        parsed_files: list[ParsedFile],
        file_contents: dict[str, str],
        ast_cache: Optional[dict[str, Any]] = None,
        call_graph: Optional[CallGraph] = None,
    ) -> dict[str, FunctionSummary]:
        """Generate summaries for all functions with fixed-point iteration for recursive calls."""
        cache = ast_cache if ast_cache is not None else {}
        resolver = CallResolver(functions) if functions else None
        current_summaries: dict[str, FunctionSummary] = {}

        # Prepare ASTs
        trees: dict[str, Any] = {}
        for pf in parsed_files:
            rel_path = pf.relative_path.replace("\\", "/")
            content = file_contents.get(rel_path, "")
            if not content:
                continue

            lang = pf.language.upper()
            if lang == "PYTHON":
                tree = cache.get(rel_path)
                if tree is None or not isinstance(tree, ast.AST):
                    try:
                        tree = ast.parse(content, filename=rel_path)
                        cache[rel_path] = tree
                    except SyntaxError:
                        continue
                trees[rel_path] = tree
            elif lang in ("JAVASCRIPT", "TYPESCRIPT"):
                root_node = cache.get(rel_path)
                if root_node is None:
                    from analyzer.parsing.javascript_parser import JavaScriptParser
                    from analyzer.parsing.typescript_parser import TypeScriptParser
                    p = TypeScriptParser() if lang == "TYPESCRIPT" else JavaScriptParser()
                    res = p.parse_string(content, rel_path)
                    if res.root_node:
                        root_node = res.root_node
                        cache[rel_path] = root_node
                if root_node is not None:
                    trees[rel_path] = root_node

        # Iterative computation until fixed point or max iterations reached
        for iteration in range(self.max_summary_iterations):
            self.check_cancellation()
            new_summaries: dict[str, FunctionSummary] = {}

            for fn_def in functions:
                self.check_cancellation()
                tree_or_node = trees.get(fn_def.file_path)
                content = file_contents.get(fn_def.file_path, "")
                if tree_or_node is None:
                    summary = FunctionSummary(
                        qualified_name=fn_def.qualified_name,
                        file_path=fn_def.file_path,
                        parameters=fn_def.parameters,
                        is_summarized=False,
                    )
                else:
                    summary = self.summarize_function(
                        fn_def=fn_def,
                        tree_or_node=tree_or_node,
                        content=content,
                        known_summaries=current_summaries,
                        resolver=resolver,
                    )
                new_summaries[fn_def.qualified_name] = summary

            # Fixed-point check: compare serialized states
            is_fixed_point = (
                len(current_summaries) == len(new_summaries)
                and all(
                    current_summaries[k].model_dump_json() == new_summaries[k].model_dump_json()
                    for k in new_summaries
                    if k in current_summaries
                )
            )

            current_summaries = new_summaries
            if is_fixed_point:
                break

        return current_summaries
