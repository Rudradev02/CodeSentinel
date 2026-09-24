"""JS/TS Tree-sitter CST alias and points-to extractor (Phase 17).

Extracts allocation sites, alias bindings, field reads/writes, and
points-to sets from JavaScript and TypeScript function bodies using
Tree-sitter CST nodes. Supports variable declarations, constructor
expressions, property assignments, property reads, and branch joins.
"""

from typing import Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.alias.models import (
    AbstractObject,
    AliasBinding,
    AliasEnvironment,
    FieldKey,
    ObjectKind,
    PointsToSet,
)
from analyzer.dataflow.alias.field_state import FieldStateMap
from analyzer.dataflow.taint.models import TaintState
from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeOrigin
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class JSTSAliasExtractor:
    """Extracts alias and points-to information from JS/TS function CSTs.

    Performs bounded intraprocedural analysis tracking:
    - Constructor expressions (const x = new ClassName())
    - Variable declarations/copies (const b = a)
    - Parameter bindings (formal param -> synthetic object)
    - Property assignments (this.field = value, obj.field = value)
    - Property reads (const r = this.field)
    - Simple branch joins (if/else)
    """

    def __init__(
        self,
        repo_classes: Optional[dict[str, str]] = None,
        max_objects_per_function: int = 32,
        max_points_to_candidates: int = 4,
        max_fields_per_object: int = 16,
        max_alias_iterations: int = 5,
        max_statements: int = 500,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.repo_classes = repo_classes or {}
        self.max_objects_per_function = max_objects_per_function
        self.max_points_to_candidates = max_points_to_candidates
        self.max_fields_per_object = max_fields_per_object
        self.max_alias_iterations = max_alias_iterations
        self.max_statements = max_statements
        self.is_cancelled = is_cancelled

    def check_cancellation(self) -> None:
        """Cooperative cancellation checkpoint."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("JS/TS alias extraction was cancelled by user")

    def extract_function_aliases(
        self,
        fn_node: Node,
        source_bytes: bytes,
        file_path: str,
        enclosing_class: Optional[str] = None,
        fn_qualified_name: Optional[str] = None,
        context_id: str = "ROOT",
    ) -> tuple[AliasEnvironment, FieldStateMap]:
        """Extract alias and field state from a JS/TS function body.

        Returns:
            Tuple of (AliasEnvironment, FieldStateMap) representing the
            analysis state at function exit.
        """
        self.check_cancellation()
        norm_path = file_path.replace("\\", "/")
        fn_name = fn_qualified_name or self._extract_function_name(fn_node, source_bytes) or "<anonymous>"

        alias_env = AliasEnvironment(
            max_objects_per_function=self.max_objects_per_function,
            max_points_to_candidates=self.max_points_to_candidates,
        )
        field_state = FieldStateMap(
            max_fields_per_object=self.max_fields_per_object,
            max_points_to_candidates=self.max_points_to_candidates,
        )

        # 1. Bind 'this' for methods
        if enclosing_class:
            class_qn = self.repo_classes.get(enclosing_class, enclosing_class)
            this_type = TypeBinding(
                type_name=enclosing_class,
                qualified_type_name=class_qn,
                confidence=TypeConfidence.KNOWN,
                origin=TypeOrigin.SELF_RECEIVER,
                source_file=norm_path,
                line=fn_node.start_point[0] + 1,
            )
            this_obj = AbstractObject.create_receiver_self_object(
                enclosing_class=enclosing_class,
                fn_qualified_name=fn_name,
                type_binding=this_type,
                context_id=context_id,
            )
            alias_env.register_object(this_obj)
            pts = PointsToSet()
            pts.add_object(this_obj.object_id, self.max_points_to_candidates)
            alias_env.set_points_to("this", pts)

        # 2. Bind formal parameters
        params_node = self._find_parameters(fn_node)
        if params_node:
            for i, param in enumerate(params_node):
                self.check_cancellation()
                param_name = node_text(param, source_bytes).strip()
                # Skip 'this' params in TS and destructured/rest params
                if not param_name or param_name == "this" or param_name.startswith("{") or param_name.startswith("..."):
                    continue
                # Handle typed params: strip type annotation
                if ":" in param_name:
                    param_name = param_name.split(":")[0].strip()

                param_type = TypeBinding(
                    type_name="Unknown",
                    qualified_type_name="Unknown",
                    confidence=TypeConfidence.UNKNOWN,
                    origin=TypeOrigin.UNRESOLVED,
                    source_file=norm_path,
                    line=param.start_point[0] + 1,
                )
                param_obj = AbstractObject.create_synthetic_parameter_object(
                    fn_qualified_name=fn_name,
                    param_index=i,
                    param_name=param_name,
                    type_binding=param_type,
                )
                alias_env.register_object(param_obj)
                pts = PointsToSet()
                pts.add_object(param_obj.object_id, self.max_points_to_candidates)
                alias_env.set_points_to(param_name, pts)

        # 3. Process function body
        body_node = self._find_body(fn_node)
        if body_node:
            self._process_statements(body_node, source_bytes, alias_env, field_state, norm_path, fn_name, context_id)

        return alias_env, field_state

    def _process_statements(
        self,
        body_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        counter: Optional[list[int]] = None,
    ) -> None:
        """Process statements in a statement block."""
        if counter is None:
            counter = [0]

        for child in body_node.children:
            counter[0] += 1
            if counter[0] > self.max_statements:
                break
            if counter[0] % 25 == 0:
                self.check_cancellation()

            child_type = child.type
            if child_type in ("variable_declaration", "lexical_declaration"):
                self._handle_declaration(child, source_bytes, alias_env, field_state, file_path, fn_qn, context_id)
            elif child_type == "expression_statement":
                self._handle_expression_statement(child, source_bytes, alias_env, field_state, file_path, fn_qn, context_id)
            elif child_type == "if_statement":
                self._handle_if(child, source_bytes, alias_env, field_state, file_path, fn_qn, context_id, counter)

    def _handle_declaration(
        self,
        decl_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
    ) -> None:
        """Handle const/let/var declarations."""
        for child in decl_node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if name_node and value_node:
                    target_name = node_text(name_node, source_bytes).strip()
                    # Handle TypeScript type annotations in name
                    if ":" in target_name:
                        target_name = target_name.split(":")[0].strip()
                    if target_name:
                        line = child.start_point[0] + 1
                        col = child.start_point[1]
                        self._handle_var_assign(
                            target_name, value_node, source_bytes,
                            alias_env, field_state, file_path, fn_qn, context_id, line, col,
                        )

    def _handle_expression_statement(
        self,
        expr_stmt: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
    ) -> None:
        """Handle expression statements (assignments, calls)."""
        expr = expr_stmt.children[0] if expr_stmt.children else None
        if not expr:
            return

        # Assignment expression: obj.field = value
        if expr.type == "assignment_expression":
            left = expr.child_by_field_name("left")
            right = expr.child_by_field_name("right")
            if left and right:
                if left.type == "member_expression":
                    obj_node = left.child_by_field_name("object")
                    prop_node = left.child_by_field_name("property")
                    if obj_node and prop_node:
                        receiver_name = node_text(obj_node, source_bytes).strip()
                        field_name = node_text(prop_node, source_bytes).strip()
                        line = expr.start_point[0] + 1
                        col = expr.start_point[1]
                        self._handle_field_write(
                            receiver_name, field_name, right, source_bytes,
                            alias_env, field_state, file_path, fn_qn, context_id, line, col,
                        )
                elif left.type == "identifier":
                    target_name = node_text(left, source_bytes).strip()
                    line = expr.start_point[0] + 1
                    col = expr.start_point[1]
                    self._handle_var_assign(
                        target_name, right, source_bytes,
                        alias_env, field_state, file_path, fn_qn, context_id, line, col,
                    )

    def _handle_var_assign(
        self,
        target_name: str,
        value_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> None:
        """Resolve RHS and strong-update the target variable's points-to set."""
        value_type = value_node.type

        # Case 1: new ClassName(...)
        if value_type == "new_expression":
            constructor_node = value_node.child_by_field_name("constructor")
            if constructor_node:
                class_name = node_text(constructor_node, source_bytes).strip()
                type_qn = self.repo_classes.get(class_name, class_name)
                tb = TypeBinding(
                    type_name=class_name,
                    qualified_type_name=type_qn,
                    confidence=TypeConfidence.KNOWN if class_name in self.repo_classes else TypeConfidence.LIKELY,
                    origin=TypeOrigin.CONSTRUCTOR,
                    source_file=file_path,
                    line=line,
                    col=col,
                )
                obj = AbstractObject.create_allocation_site_object(
                    type_binding=tb,
                    file_path=file_path,
                    line=line,
                    col=col,
                    enclosing_function=fn_qn,
                )
                alias_env.register_object(obj)
                pts = PointsToSet()
                pts.add_object(obj.object_id, self.max_points_to_candidates)
                alias_env.set_points_to(target_name, pts)
                return

        # Case 2: Identifier reference (variable copy)
        if value_type == "identifier":
            source_name = node_text(value_node, source_bytes).strip()
            source_pts = alias_env.get_points_to(source_name)
            if source_pts.candidate_ids or source_pts.is_unknown:
                alias_env.set_points_to(target_name, source_pts.copy())
                alias_env.record_alias(AliasBinding(
                    source_symbol=source_name,
                    target_symbol=target_name,
                    confidence=TypeConfidence.KNOWN if source_pts.is_singleton() else TypeConfidence.AMBIGUOUS,
                    line=line,
                    col=col,
                ))
                return

        # Case 3: Property access (member_expression): obj.field
        if value_type == "member_expression":
            obj_node = value_node.child_by_field_name("object")
            prop_node = value_node.child_by_field_name("property")
            if obj_node and prop_node:
                receiver_name = node_text(obj_node, source_bytes).strip()
                field_name = node_text(prop_node, source_bytes).strip()
                receiver_pts = alias_env.get_points_to(receiver_name)
                if receiver_pts.candidate_ids:
                    field_entry = field_state.read_field_merged(
                        context_id, receiver_pts.candidate_ids, field_name
                    )
                    if field_entry.points_to.candidate_ids or field_entry.points_to.is_unknown:
                        alias_env.set_points_to(target_name, field_entry.points_to.copy())
                        alias_env.record_alias(AliasBinding(
                            source_symbol=f"{receiver_name}.{field_name}",
                            target_symbol=target_name,
                            source_field=field_name,
                            confidence=TypeConfidence.KNOWN if receiver_pts.is_singleton() else TypeConfidence.AMBIGUOUS,
                            line=line,
                            col=col,
                        ))
                        return
            alias_env.set_points_to(target_name, PointsToSet(is_unknown=True))
            return

        # Case 4: Call expression
        if value_type == "call_expression":
            callee_node = value_node.child_by_field_name("function")
            callee_text = node_text(callee_node, source_bytes).strip() if callee_node else "<unknown>"
            tb = TypeBinding(
                type_name="Unknown",
                qualified_type_name="Unknown",
                confidence=TypeConfidence.UNKNOWN,
                origin=TypeOrigin.RETURN_SIGNATURE,
                source_file=file_path,
                line=line,
                col=col,
            )
            ret_obj = AbstractObject.create_synthetic_return_object(
                callee_qualified_name=callee_text,
                call_site_file=file_path,
                call_site_line=line,
                call_site_col=col,
                type_binding=tb,
                context_id=context_id,
            )
            alias_env.register_object(ret_obj)
            pts = PointsToSet(is_unknown=True)
            pts.add_object(ret_obj.object_id, self.max_points_to_candidates)
            alias_env.set_points_to(target_name, pts)
            return

        # Default: unknown points-to
        alias_env.set_points_to(target_name, PointsToSet(is_unknown=True))

    def _handle_field_write(
        self,
        receiver_name: str,
        field_name: str,
        value_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> None:
        """Handle property assignment: receiver.field = value."""
        receiver_pts = alias_env.get_points_to(receiver_name)
        if not receiver_pts.candidate_ids:
            return

        value_pts = self._resolve_value_pts(
            value_node, source_bytes, alias_env, field_state, file_path, fn_qn, context_id, line, col,
        )
        taint = TaintState.UNTAINTED

        field_state.write_field_for_receiver(
            context_id=context_id,
            receiver_candidate_ids=receiver_pts.candidate_ids,
            field_name=field_name,
            points_to=value_pts,
            taint_state=taint,
        )

    def _handle_if(
        self,
        if_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        counter: list[int],
    ) -> None:
        """Handle if/else with deterministic branch join."""
        consequence = if_node.child_by_field_name("consequence")
        alternative = if_node.child_by_field_name("alternative")

        then_env = alias_env.copy_for_branch()
        then_field = field_state.copy()
        if consequence:
            if consequence.type == "statement_block":
                self._process_statements(consequence, source_bytes, then_env, then_field, file_path, fn_qn, context_id, counter)
            elif consequence.type in ("variable_declaration", "lexical_declaration"):
                self._handle_declaration(consequence, source_bytes, then_env, then_field, file_path, fn_qn, context_id)
            elif consequence.type == "expression_statement":
                self._handle_expression_statement(consequence, source_bytes, then_env, then_field, file_path, fn_qn, context_id)

        if alternative:
            else_env = alias_env.copy_for_branch()
            else_field = field_state.copy()
            # alternative is typically an else_clause in Tree-sitter JS/TS
            target_node = alternative
            if alternative.type == "else_clause":
                for c in alternative.children:
                    if c.type != "else":
                        target_node = c
                        break
            if target_node.type == "statement_block":
                self._process_statements(target_node, source_bytes, else_env, else_field, file_path, fn_qn, context_id, counter)
            elif target_node.type == "if_statement":
                self._handle_if(target_node, source_bytes, else_env, else_field, file_path, fn_qn, context_id, counter)
            elif target_node.type in ("variable_declaration", "lexical_declaration"):
                self._handle_declaration(target_node, source_bytes, else_env, else_field, file_path, fn_qn, context_id)
            elif target_node.type == "expression_statement":
                self._handle_expression_statement(target_node, source_bytes, else_env, else_field, file_path, fn_qn, context_id)

            merged_env = then_env.merge_branch(else_env)
            merged_field = then_field.merge(else_field)
        else:
            merged_env = alias_env.merge_branch(then_env)
            merged_field = field_state.merge(then_field)

        # Apply merged state
        alias_env.bindings = merged_env.bindings
        alias_env.alias_evidence = merged_env.alias_evidence
        alias_env.object_store = merged_env.object_store
        alias_env.objects_allocated = merged_env.objects_allocated
        alias_env.is_truncated = merged_env.is_truncated

        field_state.entries = merged_field.entries
        field_state.field_counts = merged_field.field_counts
        field_state.overflow_objects = merged_field.overflow_objects

    def _resolve_value_pts(
        self,
        value_node: Node,
        source_bytes: bytes,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> PointsToSet:
        """Resolve a value expression to its points-to set."""
        vtype = value_node.type

        if vtype == "identifier":
            name = node_text(value_node, source_bytes).strip()
            return alias_env.get_points_to(name).copy()

        if vtype == "new_expression":
            constructor_node = value_node.child_by_field_name("constructor")
            if constructor_node:
                class_name = node_text(constructor_node, source_bytes).strip()
                type_qn = self.repo_classes.get(class_name, class_name)
                tb = TypeBinding(
                    type_name=class_name,
                    qualified_type_name=type_qn,
                    confidence=TypeConfidence.KNOWN if class_name in self.repo_classes else TypeConfidence.LIKELY,
                    origin=TypeOrigin.CONSTRUCTOR,
                    source_file=file_path,
                    line=line,
                    col=col,
                )
                obj = AbstractObject.create_allocation_site_object(
                    type_binding=tb,
                    file_path=file_path,
                    line=line,
                    col=col,
                    enclosing_function=fn_qn,
                )
                alias_env.register_object(obj)
                pts = PointsToSet()
                pts.add_object(obj.object_id, self.max_points_to_candidates)
                return pts

        if vtype == "member_expression":
            obj_node = value_node.child_by_field_name("object")
            prop_node = value_node.child_by_field_name("property")
            if obj_node and prop_node:
                receiver_name = node_text(obj_node, source_bytes).strip()
                field_name = node_text(prop_node, source_bytes).strip()
                receiver_pts = alias_env.get_points_to(receiver_name)
                if receiver_pts.candidate_ids:
                    entry = field_state.read_field_merged(
                        context_id, receiver_pts.candidate_ids, field_name,
                    )
                    return entry.points_to.copy()

        return PointsToSet(is_unknown=True)

    def _extract_function_name(self, fn_node: Node, source_bytes: bytes) -> Optional[str]:
        """Extract function name from CST node."""
        name_node = fn_node.child_by_field_name("name")
        if name_node:
            return node_text(name_node, source_bytes).strip()
        return None

    def _find_parameters(self, fn_node: Node) -> list[Node]:
        """Find formal parameter nodes."""
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            # Arrow functions may use a single identifier as parameter
            for child in fn_node.children:
                if child.type == "formal_parameters":
                    params_node = child
                    break
        if not params_node:
            return []
        return [
            child for child in params_node.children
            if child.type in ("identifier", "required_parameter", "optional_parameter")
        ]

    def _find_body(self, fn_node: Node) -> Optional[Node]:
        """Find the body/statement block of a function."""
        body = fn_node.child_by_field_name("body")
        if body:
            return body
        for child in fn_node.children:
            if child.type == "statement_block":
                return child
        return None
