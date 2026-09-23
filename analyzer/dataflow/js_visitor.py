"""Tree-sitter CST visitor executing bounded intraprocedural data-flow tracking for JS/TS."""

from typing import Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.symbol import DefinitionKind, Scope, ScopeKind, SymbolTable
from analyzer.dataflow.taint.models import SinkCategory, TaintPath, TaintSource
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class JSDataFlowAnalyzer:
    """Performs bounded intraprocedural data-flow and taint analysis on JavaScript / TypeScript CSTs."""

    def __init__(
        self,
        registry: Optional[TaintRegistry] = None,
        max_depth: int = 25,
        max_symbols: int = 100,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_depth = max_depth
        self.max_symbols = max_symbols
        self.max_statements = max_statements
        self.is_cancelled = is_cancelled

    def analyze_file(
        self,
        root_node: Node,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> list[TaintPath]:
        """Analyze all functions within a JS/TS syntax tree for taint paths."""
        results: list[TaintPath] = []
        fn_nodes = self._find_functions(root_node)

        for fn_node in fn_nodes:
            if self.is_cancelled and self.is_cancelled():
                from analyzer.models.errors import AnalysisCancelledError
                raise AnalysisCancelledError("Data-flow analysis was cancelled by user")

            paths = self.analyze_function(
                fn_node=fn_node,
                source_bytes=source_bytes,
                file_path=file_path,
                target_rule_id=target_rule_id,
            )
            results.extend(paths)

        return results

    def analyze_function(
        self,
        fn_node: Node,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> list[TaintPath]:
        """Analyze a single JS/TS function scope for taint traces."""
        propagator = TaintPropagator(
            registry=self.registry,
            max_depth=self.max_depth,
            max_symbols=self.max_symbols,
            max_statements=self.max_statements,
            is_cancelled=self.is_cancelled,
        )

        line_start, line_end, col_start, col_end = get_node_line_and_col(fn_node)
        fn_name = self._extract_function_name(fn_node, source_bytes) or "<anonymous>"

        fn_scope = Scope(
            id=Scope.create_deterministic_id(
                file_path,
                ScopeKind.FUNCTION,
                fn_name,
                line_start,
                col_start,
            ),
            name=fn_name,
            qualified_name=fn_name,
            kind=ScopeKind.FUNCTION,
            line_start=line_start,
            line_end=line_end,
            col_start=col_start,
        )

        # Register parameters
        params = self._extract_parameters(fn_node, source_bytes)
        for p in params:
            fn_scope.add_definition(
                symbol_name=p,
                kind=DefinitionKind.PARAMETER,
                line=line_start,
                col=col_start,
            )
            propagator.register_parameter(p, is_tainted=False)

        # Find body node
        body_node = fn_node.child_by_field_name("body")
        if not body_node:
            # For arrow functions with expression body
            for child in fn_node.children:
                if child.type in ("statement_block", "expression_statement"):
                    body_node = child
                    break

        if not body_node:
            return []

        # Traverse statements in body
        statements = [c for c in body_node.children if not c.type.startswith("comment")][: self.max_statements]
        self._process_statements(
            statements=statements,
            propagator=propagator,
            fn_scope=fn_scope,
            source_bytes=source_bytes,
            file_path=file_path,
            target_rule_id=target_rule_id,
        )

        return propagator.detected_paths

    def _process_statements(
        self,
        statements: list[Node],
        propagator: TaintPropagator,
        fn_scope: Scope,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Process statement sequence inside a function body."""
        stmt_count = 0
        for stmt in statements:
            stmt_count += 1
            if stmt_count % 25 == 0:
                propagator.check_cancellation()

            # Handle variable declaration: const x = ..., let y = ...
            if stmt.type in ("lexical_declaration", "variable_declaration"):
                for child in stmt.children:
                    if child.type == "variable_declarator":
                        self._handle_declarator(child, propagator, fn_scope, source_bytes, file_path)

            # Handle expression statement
            elif stmt.type == "expression_statement":
                for child in stmt.children:
                    if child.type == "assignment_expression":
                        self._handle_assignment_expr(child, propagator, fn_scope, source_bytes, file_path, target_rule_id)
                    elif child.type == "call_expression":
                        self._handle_call_expr(child, propagator, source_bytes, file_path, target_rule_id)

    def _handle_declarator(
        self,
        decl_node: Node,
        propagator: TaintPropagator,
        fn_scope: Scope,
        source_bytes: bytes,
        file_path: str,
    ) -> None:
        """Handle: const target = value."""
        name_node = decl_node.child_by_field_name("name")
        val_node = decl_node.child_by_field_name("value")
        if not name_node or not val_node:
            return

        target_sym = node_text(name_node, source_bytes).strip()
        raw_val = node_text(val_node, source_bytes).strip()
        line, _, col, _ = get_node_line_and_col(decl_node)

        fn_scope.add_definition(
            symbol_name=target_sym,
            kind=DefinitionKind.ASSIGNMENT,
            line=line,
            col=col,
            raw_expr=raw_val,
        )

        source = self._extract_source(val_node, source_bytes)
        if source:
            propagator.handle_direct_source_assignment(
                target_symbol=target_sym,
                source=source,
                line=line,
                col=col,
                expression_str=raw_val,
            )
        else:
            self._propagate_value_to_target(
                val_node=val_node,
                target_symbol=target_sym,
                propagator=propagator,
                source_bytes=source_bytes,
                line=line,
                col=col,
                raw_val=raw_val,
            )

    def _handle_assignment_expr(
        self,
        assign_node: Node,
        propagator: TaintPropagator,
        fn_scope: Scope,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Handle: target = value or element.innerHTML = value."""
        left_node = assign_node.child_by_field_name("left")
        right_node = assign_node.child_by_field_name("right")
        if not left_node or not right_node:
            return

        left_text = node_text(left_node, source_bytes).strip()
        right_text = node_text(right_node, source_bytes).strip()
        line, _, col, _ = get_node_line_and_col(assign_node)

        # 1. Is this a sink assignment? (e.g. element.innerHTML = tainted)
        if left_node.type == "member_expression":
            prop_node = left_node.child_by_field_name("property")
            prop_name = node_text(prop_node, source_bytes).strip() if prop_node else ""
            if prop_name in ("innerHTML", "outerHTML"):
                matched_sink = self.registry.find_matching_sink(
                    language="JAVASCRIPT",
                    callee_name=prop_name,
                    receiver_name="element",
                    rule_id=target_rule_id,
                )
                if matched_sink:
                    # Right side symbols
                    ref_syms = self._extract_identifier_names(right_node, source_bytes)
                    propagator.check_sink_invocation(
                        sink=matched_sink,
                        file_path=file_path,
                        line=line,
                        col=col,
                        argument_symbols=ref_syms,
                        raw_callee_expr=f"{left_text} = {right_text}",
                    )
                    return

        # 2. Regular variable assignment
        target_sym = left_text
        source = self._extract_source(right_node, source_bytes)
        if source:
            propagator.handle_direct_source_assignment(
                target_symbol=target_sym,
                source=source,
                line=line,
                col=col,
                expression_str=right_text,
            )
        else:
            self._propagate_value_to_target(
                val_node=right_node,
                target_symbol=target_sym,
                propagator=propagator,
                source_bytes=source_bytes,
                line=line,
                col=col,
                raw_val=right_text,
            )

    def _propagate_value_to_target(
        self,
        val_node: Node,
        target_symbol: str,
        propagator: TaintPropagator,
        source_bytes: bytes,
        line: int,
        col: int,
        raw_val: str,
    ) -> None:
        """Handle propagation from RHS expression to target symbol in JS/TS."""
        # 1. Sanitizer or function call
        if val_node.type == "call_expression":
            callee_node = val_node.child_by_field_name("function")
            callee_name = node_text(callee_node, source_bytes).strip() if callee_node else ""
            args_node = val_node.child_by_field_name("arguments")
            arg_syms = self._extract_identifier_names(args_node, source_bytes) if args_node else []

            # Check matching sanitizer
            matched_san = None
            for cat in [SinkCategory.DOM_INJECTION, SinkCategory.CODE_EVAL]:
                san = self.registry.find_matching_sanitizer("JAVASCRIPT", callee_name, cat)
                if san:
                    matched_san = san
                    break

            if matched_san:
                propagator.handle_sanitizer_call(
                    target_symbol=target_symbol,
                    sanitizer=matched_san,
                    argument_symbols=arg_syms,
                    line=line,
                    col=col,
                    expression_str=raw_val,
                )
                return
            else:
                # Unknown function call preserves taint
                if arg_syms:
                    propagator.handle_unknown_function_call(
                        target_symbol=target_symbol,
                        argument_symbols=arg_syms,
                        line=line,
                        col=col,
                        expression_str=raw_val,
                    )
                    return

        # 2. String concatenation (binary_expression +)
        if val_node.type == "binary_expression":
            ref_syms = self._extract_identifier_names(val_node, source_bytes)
            propagator.handle_assignment_propagation(
                target_symbol=target_symbol,
                referenced_symbols=ref_syms,
                line=line,
                col=col,
                expression_str=raw_val,
                is_binary_or_concat=True,
            )
            return

        # 3. Template literal string interpolation
        if val_node.type == "template_string":
            ref_syms = self._extract_identifier_names(val_node, source_bytes)
            propagator.handle_assignment_propagation(
                target_symbol=target_symbol,
                referenced_symbols=ref_syms,
                line=line,
                col=col,
                expression_str=raw_val,
                is_binary_or_concat=True,
            )
            return

        # 4. Direct identifier assignment or member access
        ref_syms = self._extract_identifier_names(val_node, source_bytes)
        propagator.handle_assignment_propagation(
            target_symbol=target_symbol,
            referenced_symbols=ref_syms,
            line=line,
            col=col,
            expression_str=raw_val,
            is_binary_or_concat=False,
        )

    def _handle_call_expr(
        self,
        call_node: Node,
        propagator: TaintPropagator,
        source_bytes: bytes,
        file_path: str,
        target_rule_id: Optional[str] = None,
    ) -> None:
        """Handle standalone call expressions, checking for sink execution (eval, document.write)."""
        fn_node = call_node.child_by_field_name("function")
        if not fn_node:
            return

        fn_text = node_text(fn_node, source_bytes).strip()
        line, _, col, _ = get_node_line_and_col(call_node)
        raw_call = node_text(call_node, source_bytes).strip()

        # Check document.write or document.writeln
        if fn_node.type == "member_expression":
            prop_node = fn_node.child_by_field_name("property")
            prop_name = node_text(prop_node, source_bytes).strip() if prop_node else ""
            if prop_name in ("write", "writeln"):
                matched_sink = self.registry.find_matching_sink(
                    language="JAVASCRIPT",
                    callee_name=prop_name,
                    receiver_name="document",
                    rule_id=target_rule_id,
                )
                if matched_sink:
                    args_node = call_node.child_by_field_name("arguments")
                    arg_syms = self._extract_identifier_names(args_node, source_bytes) if args_node else []
                    propagator.check_sink_invocation(
                        sink=matched_sink,
                        file_path=file_path,
                        line=line,
                        col=col,
                        argument_symbols=arg_syms,
                        raw_callee_expr=raw_call,
                    )
                    return

        # Check eval()
        if fn_text == "eval":
            matched_sink = self.registry.find_matching_sink(
                language="JAVASCRIPT",
                callee_name="eval",
                rule_id=target_rule_id,
            )
            if matched_sink:
                args_node = call_node.child_by_field_name("arguments")
                arg_syms = self._extract_identifier_names(args_node, source_bytes) if args_node else []
                propagator.check_sink_invocation(
                    sink=matched_sink,
                    file_path=file_path,
                    line=line,
                    col=col,
                    argument_symbols=arg_syms,
                    raw_callee_expr=raw_call,
                )
                return

    def _extract_source(self, node: Node, source_bytes: bytes) -> Optional[TaintSource]:
        """Check if a CST node represents a declared JS taint source."""
        if node.type == "member_expression":
            obj_node = node.child_by_field_name("object")
            prop_node = node.child_by_field_name("property")
            if obj_node and prop_node:
                obj_text = node_text(obj_node, source_bytes).strip()
                prop_text = node_text(prop_node, source_bytes).strip()

                # Handle window.location.search or location.search
                if obj_text in ("location", "window.location"):
                    return self.registry.find_matching_source(
                        language="JAVASCRIPT",
                        base_object="location",
                        member=prop_text,
                        pattern_type="ATTRIBUTE",
                    )
                # Handle document.cookie
                if obj_text in ("document", "window.document") and prop_text == "cookie":
                    return self.registry.find_matching_source(
                        language="JAVASCRIPT",
                        base_object="document",
                        member="cookie",
                        pattern_type="ATTRIBUTE",
                    )
                # Handle req.query, req.params, req.body
                if obj_text in ("req", "request"):
                    return self.registry.find_matching_source(
                        language="JAVASCRIPT",
                        base_object="req",
                        member=prop_text,
                        pattern_type="ATTRIBUTE",
                    )
        return None

    def _find_functions(self, root_node: Node) -> list[Node]:
        """Find all function-like CST nodes."""
        fns: list[Node] = []
        stack = [root_node]
        while stack:
            n = stack.pop()
            if n.type in ("function_declaration", "arrow_function", "function_expression", "method_definition"):
                fns.append(n)
            for c in reversed(n.children):
                stack.append(c)
        return fns

    def _extract_function_name(self, fn_node: Node, source_bytes: bytes) -> Optional[str]:
        """Extract name identifier for a function node."""
        name_node = fn_node.child_by_field_name("name")
        if name_node:
            return node_text(name_node, source_bytes).strip()
        return None

    def _extract_parameters(self, fn_node: Node, source_bytes: bytes) -> list[str]:
        """Extract parameter names from function formal parameters."""
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return []
        params = []
        for c in params_node.children:
            if c.type == "identifier":
                params.append(node_text(c, source_bytes).strip())
        return params

    def _extract_identifier_names(self, node: Optional[Node], source_bytes: bytes) -> list[str]:
        """Extract all identifier names in an expression."""
        if not node:
            return []
        names = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                names.append(node_text(n, source_bytes).strip())
            for c in reversed(n.children):
                stack.append(c)
        return names
