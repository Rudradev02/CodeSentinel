"""Native Python AST visitor executing bounded intraprocedural data-flow tracking."""

import ast
from typing import Any, Callable, Optional

from analyzer.dataflow.cfg.guard_evaluator import GuardEvaluator
from analyzer.dataflow.symbol import DefinitionKind, Scope, ScopeKind, SymbolTable
from analyzer.dataflow.taint.models import SinkCategory, TaintPath, TaintSource, TaintState
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry


class PythonDataFlowAnalyzer:
    """Performs bounded intraprocedural data-flow and taint analysis on Python ASTs."""

    def __init__(
        self,
        registry: Optional[TaintRegistry] = None,
        max_depth: int = 25,
        max_symbols: int = 100,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
        guard_evaluator: Optional[GuardEvaluator] = None,
        disable_guard_analysis: bool = False,
    ):
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_depth = max_depth
        self.max_symbols = max_symbols
        self.max_statements = max_statements
        self.is_cancelled = is_cancelled
        self.guard_evaluator = guard_evaluator or GuardEvaluator()
        self.disable_guard_analysis = disable_guard_analysis

    def analyze_file(
        self,
        tree: ast.AST,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> list[TaintPath]:
        """Analyze all functions in a Python AST file for taint paths."""
        results: list[TaintPath] = []
        symbol_table = SymbolTable()

        # Module-level root scope
        mod_scope = Scope(
            id=Scope.create_deterministic_id(file_path, ScopeKind.MODULE, "<module>", 1, 0),
            name="<module>",
            qualified_name="<module>",
            kind=ScopeKind.MODULE,
            line_start=1,
            line_end=getattr(tree, "end_lineno", 1000) or 1000,
        )
        symbol_table.add_scope(mod_scope)

        # Walk AST to find functions
        for node in ast.walk(tree):
            if self.is_cancelled and self.is_cancelled():
                from analyzer.models.errors import AnalysisCancelledError
                raise AnalysisCancelledError("Data-flow analysis was cancelled by user")

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_paths = self.analyze_function(
                    node=node,
                    file_path=file_path,
                    parent_scope_id=mod_scope.id,
                    target_rule_id=target_rule_id,
                )
                results.extend(fn_paths)

        return results

    def analyze_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        parent_scope_id: Optional[str] = None,
        target_rule_id: Optional[str] = None,
    ) -> list[TaintPath]:
        """Analyze a single function scope for source-to-sink data-flow traces."""
        propagator = TaintPropagator(
            registry=self.registry,
            max_depth=self.max_depth,
            max_symbols=self.max_symbols,
            max_statements=self.max_statements,
            is_cancelled=self.is_cancelled,
        )

        fn_scope = Scope(
            id=Scope.create_deterministic_id(
                file_path,
                ScopeKind.FUNCTION if isinstance(node, ast.FunctionDef) else ScopeKind.ASYNC_FUNCTION,
                node.name,
                node.lineno,
                node.col_offset,
            ),
            name=node.name,
            qualified_name=node.name,
            kind=ScopeKind.FUNCTION if isinstance(node, ast.FunctionDef) else ScopeKind.ASYNC_FUNCTION,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            col_start=node.col_offset,
            parent_id=parent_scope_id,
        )

        # Register parameters
        for arg in node.args.args:
            fn_scope.add_definition(
                symbol_name=arg.arg,
                kind=DefinitionKind.PARAMETER,
                line=arg.lineno if hasattr(arg, "lineno") else node.lineno,
                col=arg.col_offset if hasattr(arg, "col_offset") else 0,
            )
            propagator.register_parameter(arg.arg, is_tainted=False)

        # Process statements sequentially with bounded statements limit
        statements = node.body[: self.max_statements]
        self._process_statements(
            statements=statements,
            propagator=propagator,
            fn_scope=fn_scope,
            file_path=file_path,
            target_rule_id=target_rule_id,
        )

        return propagator.detected_paths

    def _process_statements(
        self,
        statements: list[ast.stmt],
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str] = None,
        statement_counter: Optional[list[int]] = None,
    ) -> None:
        """Process a block of statements within a function."""
        if statement_counter is None:
            statement_counter = [0]

        for stmt in statements:
            statement_counter[0] += 1
            if statement_counter[0] % 25 == 0:
                propagator.check_cancellation()

            if isinstance(stmt, (ast.Return, ast.Raise)):
                break
            elif isinstance(stmt, ast.Assign):
                self._handle_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.AnnAssign):
                self._handle_ann_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.AugAssign):
                self._handle_aug_assign(stmt, propagator, fn_scope, file_path)
            elif isinstance(stmt, ast.Expr):
                self._handle_expr_stmt(stmt, propagator, fn_scope, file_path, target_rule_id)
            elif isinstance(stmt, ast.Assert):
                self._handle_assert_stmt(stmt, propagator)
            elif isinstance(stmt, ast.If):
                self._handle_if_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            elif isinstance(stmt, (ast.For, ast.While)):
                self._handle_loop_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            elif isinstance(stmt, ast.Try):
                self._handle_try_stmt(stmt, propagator, fn_scope, file_path, target_rule_id, statement_counter)

    def _handle_assign(
        self,
        stmt: ast.Assign,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
    ) -> None:
        """Handle variable assignment: x = expr or a, b = expr1, expr2."""
        raw_rhs = ast.unparse(stmt.value) if hasattr(ast, "unparse") else "<expr>"
        
        # Check if RHS is a direct taint source
        source = self._extract_source(stmt.value)

        # Collect targets
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                target_sym = target.id
                fn_scope.add_definition(
                    symbol_name=target_sym,
                    kind=DefinitionKind.ASSIGNMENT,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                    raw_expr=raw_rhs,
                )

                if source:
                    propagator.handle_direct_source_assignment(
                        target_symbol=target_sym,
                        source=source,
                        line=stmt.lineno,
                        col=stmt.col_offset,
                        expression_str=raw_rhs,
                    )
                else:
                    self._propagate_rhs_to_target(
                        rhs_node=stmt.value,
                        target_symbol=target_sym,
                        propagator=propagator,
                        line=stmt.lineno,
                        col=stmt.col_offset,
                        raw_rhs=raw_rhs,
                    )
            elif isinstance(target, (ast.Tuple, ast.List)):
                # Tuple unpacking: a, b = src, "safe"
                if isinstance(stmt.value, (ast.Tuple, ast.List)) and len(target.elts) == len(stmt.value.elts):
                    for t_elt, v_elt in zip(target.elts, stmt.value.elts):
                        if isinstance(t_elt, ast.Name):
                            t_sym = t_elt.id
                            v_raw = ast.unparse(v_elt) if hasattr(ast, "unparse") else "<expr>"
                            v_src = self._extract_source(v_elt)
                            if v_src:
                                propagator.handle_direct_source_assignment(
                                    target_symbol=t_sym,
                                    source=v_src,
                                    line=stmt.lineno,
                                    col=stmt.col_offset,
                                    expression_str=v_raw,
                                )
                            else:
                                self._propagate_rhs_to_target(
                                    rhs_node=v_elt,
                                    target_symbol=t_sym,
                                    propagator=propagator,
                                    line=stmt.lineno,
                                    col=stmt.col_offset,
                                    raw_rhs=v_raw,
                                )

    def _handle_ann_assign(
        self,
        stmt: ast.AnnAssign,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
    ) -> None:
        """Handle annotated assignment: x: str = expr."""
        if not stmt.value or not isinstance(stmt.target, ast.Name):
            return
        target_sym = stmt.target.id
        raw_rhs = ast.unparse(stmt.value) if hasattr(ast, "unparse") else "<expr>"
        fn_scope.add_definition(
            symbol_name=target_sym,
            kind=DefinitionKind.ASSIGNMENT,
            line=stmt.lineno,
            col=stmt.col_offset,
            raw_expr=raw_rhs,
        )
        source = self._extract_source(stmt.value)
        if source:
            propagator.handle_direct_source_assignment(
                target_symbol=target_sym,
                source=source,
                line=stmt.lineno,
                col=stmt.col_offset,
                expression_str=raw_rhs,
            )
        else:
            self._propagate_rhs_to_target(
                rhs_node=stmt.value,
                target_symbol=target_sym,
                propagator=propagator,
                line=stmt.lineno,
                col=stmt.col_offset,
                raw_rhs=raw_rhs,
            )

    def _handle_aug_assign(
        self,
        stmt: ast.AugAssign,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
    ) -> None:
        """Handle augmented assignment: x += y."""
        if not isinstance(stmt.target, ast.Name):
            return
        target_sym = stmt.target.id
        raw_rhs = ast.unparse(stmt.value) if hasattr(ast, "unparse") else "<expr>"
        referenced_syms = [s for s in self._extract_names(stmt.value)] + [target_sym]
        propagator.handle_assignment_propagation(
            target_symbol=target_sym,
            referenced_symbols=referenced_syms,
            line=stmt.lineno,
            col=stmt.col_offset,
            expression_str=f"{target_sym} += {raw_rhs}",
            is_binary_or_concat=True,
        )

    def _propagate_rhs_to_target(
        self,
        rhs_node: ast.AST,
        target_symbol: str,
        propagator: TaintPropagator,
        line: int,
        col: int,
        raw_rhs: str,
    ) -> None:
        """Determine RHS evaluation and update propagator."""
        # 1. Is RHS a sanitizer call? (e.g. int(x), float(x), shlex.quote(x))
        if isinstance(rhs_node, ast.Call):
            callee_name = self._get_call_name(rhs_node)
            arg_names = []
            for a in rhs_node.args:
                arg_names.extend(self._extract_names(a))

            # Check if matching sanitizer exists for SQL or Command
            matched_san = None
            for cat in [SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE]:
                san = self.registry.find_matching_sanitizer("PYTHON", callee_name, cat)
                if san:
                    matched_san = san
                    break

            if matched_san:
                embedded_src_in_arg = None
                for a in rhs_node.args:
                    embedded_src_in_arg = self._find_any_source(a)
                    if embedded_src_in_arg:
                        break

                propagator.handle_sanitizer_call(
                    target_symbol=target_symbol,
                    sanitizer=matched_san,
                    argument_symbols=arg_names,
                    line=line,
                    col=col,
                    expression_str=raw_rhs,
                    embedded_source=embedded_src_in_arg,
                )
                return

        # 2. Check if an untrusted source is directly embedded anywhere in the RHS expression
        embedded_src = self._find_any_source(rhs_node)
        if embedded_src:
            propagator.handle_direct_source_assignment(
                target_symbol=target_symbol,
                source=embedded_src,
                line=line,
                col=col,
                expression_str=raw_rhs,
            )
            return

        # 3. If it was an unknown call (and had no embedded source):
        # Unknown function call! Unknown functions NEVER clear taint.
        if isinstance(rhs_node, ast.Call):
            if arg_names:
                propagator.handle_unknown_function_call(
                    target_symbol=target_symbol,
                    argument_symbols=arg_names,
                    line=line,
                    col=col,
                    expression_str=raw_rhs,
                )
                return

        # 2. Binary operations (e.g. "SELECT " + uid)
        if isinstance(rhs_node, ast.BinOp):
            referenced_syms = self._extract_names(rhs_node)
            propagator.handle_assignment_propagation(
                target_symbol=target_symbol,
                referenced_symbols=referenced_syms,
                line=line,
                col=col,
                expression_str=raw_rhs,
                is_binary_or_concat=True,
            )
            return

        # 3. Formatted strings (f-strings: f"SELECT {uid}")
        if isinstance(rhs_node, ast.JoinedStr):
            referenced_syms = self._extract_names(rhs_node)
            propagator.handle_assignment_propagation(
                target_symbol=target_symbol,
                referenced_symbols=referenced_syms,
                line=line,
                col=col,
                expression_str=raw_rhs,
                is_binary_or_concat=True,
            )
            return

        # 4. Direct symbol reference or container subscript (y = x, y = container[k])
        referenced_syms = self._extract_names(rhs_node)
        propagator.handle_assignment_propagation(
            target_symbol=target_symbol,
            referenced_symbols=referenced_syms,
            line=line,
            col=col,
            expression_str=raw_rhs,
            is_binary_or_concat=False,
        )

    def _handle_expr_stmt(
        self,
        stmt: ast.Expr,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Handle standalone expression statements, primarily sink invocations (e.g. cursor.execute(query))."""
        if isinstance(stmt.value, ast.Call):
            self._check_call_for_sink(
                call_node=stmt.value,
                propagator=propagator,
                file_path=file_path,
                target_rule_id=target_rule_id,
            )

    def _check_call_for_sink(
        self,
        call_node: ast.Call,
        propagator: TaintPropagator,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Inspect a call node to evaluate potential sensitive sink execution."""
        callee_name = self._get_call_name(call_node)
        receiver_name = self._get_receiver_name(call_node)

        # Match against Python sinks
        matched_sink = self.registry.find_matching_sink(
            language="PYTHON",
            callee_name=callee_name,
            receiver_name=receiver_name,
            rule_id=target_rule_id,
        )

        if not matched_sink:
            return

        # Extract argument symbols and raw callee expression
        raw_callee = ast.unparse(call_node) if hasattr(ast, "unparse") else callee_name
        arg_symbols: list[str] = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name):
                arg_symbols.append(arg.id)
            else:
                names = self._extract_names(arg)
                arg_symbols.append(names[0] if names else "")

        # Check for parameterized SQL query binding
        is_parameterized = False
        if matched_sink.supports_parameter_binding:
            # e.g. cursor.execute("SELECT ...", (id,)) has >= 2 arguments or kwargs 'params'
            if len(call_node.args) >= 2 or any(k.arg in ("params", "parameters") for k in call_node.keywords):
                is_parameterized = True

        propagator.check_sink_invocation(
            sink=matched_sink,
            file_path=file_path,
            line=call_node.lineno,
            col=call_node.col_offset,
            argument_symbols=arg_symbols,
            raw_callee_expr=raw_callee,
            is_query_parameterized=is_parameterized,
        )

    def _handle_assert_stmt(
        self,
        stmt: ast.Assert,
        propagator: TaintPropagator,
    ) -> None:
        """Handle assert condition: True continuation continues with refinements, False raises AssertionError."""
        if not self.disable_guard_analysis:
            _, true_facts = self.guard_evaluator.evaluate_python_condition(stmt.test, expected_value=True)
            for f in true_facts:
                propagator.add_symbol_refinement(f.variable_name, f)

    def _has_unconditional_early_exit(self, stmts: list[ast.stmt]) -> bool:
        """Check if statement sequence unconditionally exits via return, raise, sys.exit, or abort."""
        for s in stmts:
            if isinstance(s, (ast.Return, ast.Raise)):
                return True
            if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                call = s.value
                callee_name = ""
                if isinstance(call.func, ast.Name):
                    callee_name = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    callee_name = call.func.attr
                if callee_name in ("exit", "abort"):
                    return True
        return False

    def _handle_if_stmt(
        self,
        stmt: ast.If,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str],
        statement_counter: list[int],
    ) -> None:
        """Handle branching: evaluate guards, prune early-exit paths, and perform conservative lattice merge."""
        pre_states = dict(propagator.symbol_states)
        pre_traces = {k: list(v) for k, v in propagator.symbol_traces.items()}
        pre_sanitizers = {k: list(v) for k, v in propagator.symbol_sanitizers.items()}
        pre_refinements = {k: list(v) for k, v in propagator.symbol_refinements.items()}

        body_exits = self._has_unconditional_early_exit(stmt.body)
        orelse_exits = self._has_unconditional_early_exit(stmt.orelse) if stmt.orelse else False

        # Evaluate guards if enabled
        true_facts = []
        false_facts = []
        if not self.disable_guard_analysis:
            _, true_facts = self.guard_evaluator.evaluate_python_condition(stmt.test, expected_value=True)
            _, false_facts = self.guard_evaluator.evaluate_python_condition(stmt.test, expected_value=False)

        # 1. Process True branch
        for f in true_facts:
            propagator.add_symbol_refinement(f.variable_name, f)
        self._process_statements(stmt.body, propagator, fn_scope, file_path, target_rule_id, statement_counter)
        body_states = dict(propagator.symbol_states)
        body_traces = {k: list(v) for k, v in propagator.symbol_traces.items()}
        body_sans = {k: list(v) for k, v in propagator.symbol_sanitizers.items()}
        body_refinements = {k: list(v) for k, v in propagator.symbol_refinements.items()}

        # 2. Reset and process False branch
        propagator.symbol_states = dict(pre_states)
        propagator.symbol_traces = {k: list(v) for k, v in pre_traces.items()}
        propagator.symbol_sanitizers = {k: list(v) for k, v in pre_sanitizers.items()}
        propagator.symbol_refinements = {k: list(v) for k, v in pre_refinements.items()}
        for f in false_facts:
            propagator.add_symbol_refinement(f.variable_name, f)

        if stmt.orelse:
            self._process_statements(stmt.orelse, propagator, fn_scope, file_path, target_rule_id, statement_counter)
        orelse_states = dict(propagator.symbol_states)
        orelse_traces = {k: list(v) for k, v in propagator.symbol_traces.items()}
        orelse_sans = {k: list(v) for k, v in propagator.symbol_sanitizers.items()}
        orelse_refinements = {k: list(v) for k, v in propagator.symbol_refinements.items()}

        # 3. Reachability and Lattice Merge:
        # Case A: Body exits early, no orelse -> downstream continues ONLY along the False continuation!
        if body_exits and not stmt.orelse:
            propagator.symbol_states = orelse_states
            propagator.symbol_traces = orelse_traces
            propagator.symbol_sanitizers = orelse_sans
            propagator.symbol_refinements = orelse_refinements
            return

        # Case B: Orelse exits early, body does not -> downstream continues ONLY along True branch!
        if orelse_exits and not body_exits:
            propagator.symbol_states = body_states
            propagator.symbol_traces = body_traces
            propagator.symbol_sanitizers = body_sans
            propagator.symbol_refinements = body_refinements
            return

        # Case C: Both branches exit early -> function terminates, nothing continues downstream
        if body_exits and orelse_exits:
            propagator.symbol_states = {}
            propagator.symbol_traces = {}
            propagator.symbol_sanitizers = {}
            propagator.symbol_refinements = {}
            return

        # Case D: Both branches can reach downstream -> Conservative lattice merge
        all_symbols = set(body_states.keys()).union(set(orelse_states.keys()))
        for sym in all_symbols:
            s_body = body_states.get(sym, pre_states.get(sym, None))
            s_orelse = orelse_states.get(sym, pre_states.get(sym, None))
            if s_body and s_orelse:
                merged_state = s_body.__class__.merge(s_body, s_orelse)
                propagator.symbol_states[sym] = merged_state
                if merged_state == s_body:
                    propagator.symbol_traces[sym] = body_traces.get(sym, [])
                    propagator.symbol_sanitizers[sym] = body_sans.get(sym, [])
                else:
                    propagator.symbol_traces[sym] = orelse_traces.get(sym, [])
                    propagator.symbol_sanitizers[sym] = orelse_sans.get(sym, [])
            elif s_body:
                propagator.symbol_states[sym] = s_body
                propagator.symbol_traces[sym] = body_traces.get(sym, [])
                propagator.symbol_sanitizers[sym] = body_sans.get(sym, [])
            elif s_orelse:
                propagator.symbol_states[sym] = s_orelse
                propagator.symbol_traces[sym] = orelse_traces.get(sym, [])
                propagator.symbol_sanitizers[sym] = orelse_sans.get(sym, [])

        # Monotonic intersection of refinements across both merging paths
        merged_refinements: dict[str, list[Any]] = {}
        for var, r_body in body_refinements.items():
            if var in orelse_refinements:
                r_orelse = orelse_refinements[var]
                common = [
                    fb for fb in r_body
                    if any(
                        (fb.refined_type and fb.refined_type == fo.refined_type) or
                        (fb.is_numeric_string and fo.is_numeric_string) or
                        (fb.is_alphanumeric_string and fo.is_alphanumeric_string)
                        for fo in r_orelse
                    )
                ]
                if common:
                    merged_refinements[var] = common
        propagator.symbol_refinements = merged_refinements

    def _handle_loop_stmt(
        self,
        stmt: ast.For | ast.While,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str],
        statement_counter: list[int],
    ) -> None:
        """Evaluate loop bodies with fixed-point limit of 2 iterations."""
        for _ in range(2):
            self._process_statements(stmt.body, propagator, fn_scope, file_path, target_rule_id, statement_counter)

    def _handle_try_stmt(
        self,
        stmt: ast.Try,
        propagator: TaintPropagator,
        fn_scope: Scope,
        file_path: str,
        target_rule_id: Optional[str],
        statement_counter: list[int],
    ) -> None:
        """Evaluate try body and exception handlers with conservative lattice merge."""
        pre_states = dict(propagator.symbol_states)
        pre_traces = {k: list(v) for k, v in propagator.symbol_traces.items()}
        pre_sanitizers = {k: list(v) for k, v in propagator.symbol_sanitizers.items()}

        # 1. Evaluate Try block
        self._process_statements(stmt.body, propagator, fn_scope, file_path, target_rule_id, statement_counter)
        try_states = dict(propagator.symbol_states)
        try_traces = {k: list(v) for k, v in propagator.symbol_traces.items()}
        try_sans = {k: list(v) for k, v in propagator.symbol_sanitizers.items()}

        # 2. Evaluate Handlers
        handler_states_list = []
        handler_traces_list = []
        handler_sans_list = []

        for handler in stmt.handlers:
            propagator.symbol_states = dict(pre_states)
            propagator.symbol_traces = {k: list(v) for k, v in pre_traces.items()}
            propagator.symbol_sanitizers = {k: list(v) for k, v in pre_sanitizers.items()}
            self._process_statements(handler.body, propagator, fn_scope, file_path, target_rule_id, statement_counter)
            handler_states_list.append(dict(propagator.symbol_states))
            handler_traces_list.append({k: list(v) for k, v in propagator.symbol_traces.items()})
            handler_sans_list.append({k: list(v) for k, v in propagator.symbol_sanitizers.items()})

        # 3. Conservative lattice merge: TAINTED | UNTAINTED = TAINTED
        all_branches = [try_states] + handler_states_list
        all_traces = [try_traces] + handler_traces_list
        all_sans = [try_sans] + handler_sans_list

        all_syms = set()
        for b in all_branches:
            all_syms.update(b.keys())

        for sym in all_syms:
            merged_state = TaintState.UNTAINTED
            chosen_trace = []
            chosen_san = []
            for b_idx, b in enumerate(all_branches):
                s = b.get(sym, pre_states.get(sym, TaintState.UNTAINTED))
                merged_state = TaintState.merge(merged_state, s)
                if s == TaintState.TAINTED and not chosen_trace:
                    chosen_trace = all_traces[b_idx].get(sym, [])
                    chosen_san = all_sans[b_idx].get(sym, [])

            propagator.symbol_states[sym] = merged_state
            if chosen_trace:
                propagator.symbol_traces[sym] = chosen_trace
                propagator.symbol_sanitizers[sym] = chosen_san
            elif try_traces.get(sym):
                propagator.symbol_traces[sym] = try_traces.get(sym, [])
                propagator.symbol_sanitizers[sym] = try_sans.get(sym, [])

    def _find_any_source(self, node: ast.AST) -> Optional[TaintSource]:
        """Search subtrees recursively for any direct taint source."""
        for n in ast.walk(node):
            src = self._extract_source(n)
            if src:
                return src
        return None

    def _extract_source(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if an AST node is a declared taint source."""
        # 1. Subscript: request.args['id'] or request.GET['id'] or os.environ['VAR']
        if isinstance(node, ast.Subscript):
            base_name = self._get_full_attr_name(node.value)
            if base_name:
                parts = base_name.split(".")
                if len(parts) >= 2:
                    return self.registry.find_matching_source(
                        language="PYTHON",
                        base_object=parts[0],
                        member=parts[1],
                        pattern_type="SUBSCRIPT",
                    )
                elif base_name == "os.environ":
                    return self.registry.find_matching_source(
                        language="PYTHON",
                        base_object="os.environ",
                        member="environ",
                        pattern_type="SUBSCRIPT",
                    )

        # 2. Attribute: request.args or request.GET
        if isinstance(node, ast.Attribute):
            base_name = self._get_full_attr_name(node.value)
            return self.registry.find_matching_source(
                language="PYTHON",
                base_object=base_name,
                member=node.attr,
                pattern_type="ATTRIBUTE",
            )

        # 3. Call: request.get_json() or os.getenv('VAR') or request.args.get('id')
        if isinstance(node, ast.Call):
            callee_name = self._get_call_name(node)
            receiver_name = self._get_receiver_name(node)
            # Check request.args.get('id') -> request.args is source
            if callee_name == "get" and receiver_name:
                parts = receiver_name.split(".")
                if len(parts) >= 2 and parts[0] == "request":
                    return self.registry.find_matching_source(
                        language="PYTHON",
                        base_object=parts[0],
                        member=parts[1],
                        pattern_type="SUBSCRIPT",
                    )
            # Check os.getenv
            if callee_name == "getenv" and receiver_name == "os":
                return self.registry.find_matching_source(
                    language="PYTHON",
                    base_object="os",
                    member="getenv",
                    pattern_type="CALL",
                )
            # Check request.get_json()
            if callee_name == "get_json" and receiver_name == "request":
                return self.registry.find_matching_source(
                    language="PYTHON",
                    base_object="request",
                    member="get_json",
                    pattern_type="CALL",
                )

        return None

    def _extract_names(self, node: ast.AST) -> list[str]:
        """Extract all identifier names appearing within an expression."""
        names: list[str] = []
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                names.append(n.id)
        return names

    def _get_call_name(self, call_node: ast.Call) -> str:
        """Extract the terminal function name being called."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr
        return ""

    def _get_receiver_name(self, call_node: ast.Call) -> str:
        """Extract the receiver object string (e.g. 'cursor' or 'subprocess')."""
        if isinstance(call_node.func, ast.Attribute):
            return self._get_full_attr_name(call_node.func.value) or ""
        return ""

    def _get_full_attr_name(self, node: ast.AST) -> Optional[str]:
        """Recursively resolve dot-separated attribute names (e.g. 'os.environ')."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            prefix = self._get_full_attr_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return None
