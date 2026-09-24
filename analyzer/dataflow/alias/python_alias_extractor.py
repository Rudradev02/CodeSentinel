"""Python AST alias and points-to extractor (Phase 17).

Extracts allocation sites, alias bindings, field reads/writes, and
points-to sets from Python function bodies using the AST. Supports
local variable assignments, parameter bindings, constructor calls,
attribute access, return values, and simple branch joins.
"""

import ast
from typing import Any, Callable, Optional

from analyzer.dataflow.alias.models import (
    AbstractObject,
    AliasBinding,
    AliasEnvironment,
    AllocationSite,
    FieldKey,
    ObjectKind,
    PointsToSet,
)
from analyzer.dataflow.alias.field_state import FieldStateMap
from analyzer.dataflow.taint.models import TaintState
from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeOrigin


class PythonAliasExtractor:
    """Extracts alias and points-to information from Python function ASTs.

    Performs bounded intraprocedural analysis tracking:
    - Constructor allocations (x = ClassName())
    - Variable copies (b = a)
    - Parameter bindings (formal param -> synthetic object)
    - Attribute writes (self.field = value)
    - Attribute reads (var = self.field)
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
            raise AnalysisCancelledError("Alias extraction was cancelled by user")

    def extract_function_aliases(
        self,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        enclosing_class: Optional[str] = None,
        fn_qualified_name: Optional[str] = None,
        context_id: str = "ROOT",
    ) -> tuple[AliasEnvironment, FieldStateMap]:
        """Extract alias and field state from a Python function body.

        Returns:
            Tuple of (AliasEnvironment, FieldStateMap) representing the
            analysis state at function exit.
        """
        self.check_cancellation()
        norm_path = file_path.replace("\\", "/")
        qn = fn_qualified_name or fn_node.name

        alias_env = AliasEnvironment(
            max_objects_per_function=self.max_objects_per_function,
            max_points_to_candidates=self.max_points_to_candidates,
        )
        field_state = FieldStateMap(
            max_fields_per_object=self.max_fields_per_object,
            max_points_to_candidates=self.max_points_to_candidates,
        )

        # 1. Bind 'self'/'cls' for methods
        if enclosing_class:
            class_qn = self.repo_classes.get(enclosing_class, enclosing_class)
            self_type = TypeBinding(
                type_name=enclosing_class,
                qualified_type_name=class_qn,
                confidence=TypeConfidence.KNOWN,
                origin=TypeOrigin.SELF_RECEIVER,
                source_file=norm_path,
                line=fn_node.lineno,
            )
            self_obj = AbstractObject.create_receiver_self_object(
                enclosing_class=enclosing_class,
                fn_qualified_name=qn,
                type_binding=self_type,
                context_id=context_id,
            )
            alias_env.register_object(self_obj)
            pts = PointsToSet()
            pts.add_object(self_obj.object_id, self.max_points_to_candidates)
            alias_env.set_points_to("self", pts)

        # 2. Bind formal parameters
        for i, arg in enumerate(fn_node.args.args):
            self.check_cancellation()
            if arg.arg in ("self", "cls"):
                continue
            type_name = "Unknown"
            type_qn = "Unknown"
            confidence = TypeConfidence.UNKNOWN
            origin = TypeOrigin.UNRESOLVED
            if arg.annotation:
                ann_name = self._resolve_annotation(arg.annotation)
                if ann_name:
                    type_name = ann_name
                    type_qn = self.repo_classes.get(ann_name, ann_name)
                    confidence = TypeConfidence.KNOWN if ann_name in self.repo_classes else TypeConfidence.LIKELY
                    origin = TypeOrigin.TYPE_ANNOTATION

            param_type = TypeBinding(
                type_name=type_name,
                qualified_type_name=type_qn,
                confidence=confidence,
                origin=origin,
                source_file=norm_path,
                line=fn_node.lineno,
            )
            param_obj = AbstractObject.create_synthetic_parameter_object(
                fn_qualified_name=qn,
                param_index=i,
                param_name=arg.arg,
                type_binding=param_type,
            )
            alias_env.register_object(param_obj)
            pts = PointsToSet()
            pts.add_object(param_obj.object_id, self.max_points_to_candidates)
            alias_env.set_points_to(arg.arg, pts)

        # 3. Process function body statements
        self._process_statements(
            fn_node.body[:self.max_statements],
            alias_env,
            field_state,
            norm_path,
            qn,
            context_id,
        )

        return alias_env, field_state

    def _process_statements(
        self,
        statements: list[ast.stmt],
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        counter: Optional[list[int]] = None,
    ) -> None:
        """Process a sequence of statements updating alias and field state."""
        if counter is None:
            counter = [0]

        for stmt in statements:
            counter[0] += 1
            if counter[0] > self.max_statements:
                break
            if counter[0] % 25 == 0:
                self.check_cancellation()

            if isinstance(stmt, ast.Assign):
                self._handle_assign(stmt, alias_env, field_state, file_path, fn_qn, context_id)
            elif isinstance(stmt, ast.AnnAssign):
                self._handle_ann_assign(stmt, alias_env, field_state, file_path, fn_qn, context_id)
            elif isinstance(stmt, ast.If):
                self._handle_if(stmt, alias_env, field_state, file_path, fn_qn, context_id, counter)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self._handle_expr_call(stmt, alias_env, field_state, file_path, fn_qn, context_id)

    def _handle_assign(
        self,
        stmt: ast.Assign,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
    ) -> None:
        """Handle assignment statements: x = expr, self.field = expr."""
        if stmt.value is None:
            return

        for target in stmt.targets:
            # Field write: self.field = value or obj.field = value
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                self._handle_field_write(
                    receiver_name=target.value.id,
                    field_name=target.attr,
                    value_node=stmt.value,
                    alias_env=alias_env,
                    field_state=field_state,
                    file_path=file_path,
                    fn_qn=fn_qn,
                    context_id=context_id,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                )
                continue

            # Variable assignment: x = expr
            if isinstance(target, ast.Name):
                self._handle_var_assign(
                    target_name=target.id,
                    value_node=stmt.value,
                    alias_env=alias_env,
                    field_state=field_state,
                    file_path=file_path,
                    fn_qn=fn_qn,
                    context_id=context_id,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                )

    def _handle_ann_assign(
        self,
        stmt: ast.AnnAssign,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
    ) -> None:
        """Handle annotated assignments: x: Type = expr."""
        if stmt.value is None:
            return
        if isinstance(stmt.target, ast.Name):
            self._handle_var_assign(
                target_name=stmt.target.id,
                value_node=stmt.value,
                alias_env=alias_env,
                field_state=field_state,
                file_path=file_path,
                fn_qn=fn_qn,
                context_id=context_id,
                line=stmt.lineno,
                col=stmt.col_offset,
            )
        elif isinstance(stmt.target, ast.Attribute) and isinstance(stmt.target.value, ast.Name):
            self._handle_field_write(
                receiver_name=stmt.target.value.id,
                field_name=stmt.target.attr,
                value_node=stmt.value,
                alias_env=alias_env,
                field_state=field_state,
                file_path=file_path,
                fn_qn=fn_qn,
                context_id=context_id,
                line=stmt.lineno,
                col=stmt.col_offset,
            )

    def _handle_var_assign(
        self,
        target_name: str,
        value_node: ast.expr,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> None:
        """Resolve RHS and strong-update the target variable's points-to set."""
        # Case 1: Constructor call: x = ClassName(...)
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name):
            func_name = value_node.func.id
            if func_name[0].isupper():  # Heuristic for class constructors
                type_qn = self.repo_classes.get(func_name, func_name)
                tb = TypeBinding(
                    type_name=func_name,
                    qualified_type_name=type_qn,
                    confidence=TypeConfidence.KNOWN if func_name in self.repo_classes else TypeConfidence.LIKELY,
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

        # Case 2: Attribute access: x = obj.field or x = self.field
        if isinstance(value_node, ast.Attribute) and isinstance(value_node.value, ast.Name):
            receiver_name = value_node.value.id
            field_name = value_node.attr
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
            # Fallback: assign unknown points-to for unresolved field
            alias_env.set_points_to(target_name, PointsToSet(is_unknown=True))
            return

        # Case 3: Variable copy: x = y
        if isinstance(value_node, ast.Name):
            source_name = value_node.id
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

        # Case 4: Method call with attribute receiver: x = obj.method(...)
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Attribute):
            if isinstance(value_node.func.value, ast.Name):
                # Record return object placeholder
                callee_expr = f"{value_node.func.value.id}.{value_node.func.attr}"
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
                    callee_qualified_name=callee_expr,
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

        # Case 5: Standalone function call: x = func_name(...)
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name):
            func_name = value_node.func.id
            # Not a constructor (handled above), treat as function call return
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
                callee_qualified_name=func_name,
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

        # Default: no alias information extracted
        alias_env.set_points_to(target_name, PointsToSet(is_unknown=True))

    def _handle_field_write(
        self,
        receiver_name: str,
        field_name: str,
        value_node: ast.expr,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> None:
        """Handle field assignment: receiver.field = value."""
        receiver_pts = alias_env.get_points_to(receiver_name)
        if not receiver_pts.candidate_ids:
            return  # Unknown receiver, can't track fields

        # Resolve value points-to
        value_pts = self._resolve_value_pts(value_node, alias_env, field_state, file_path, fn_qn, context_id, line, col)

        # Resolve value taint (default: untainted for alias extraction stage)
        taint = TaintState.UNTAINTED

        # Resolve type binding from value
        value_type: Optional[TypeBinding] = None
        if isinstance(value_node, ast.Name):
            src_pts = alias_env.get_points_to(value_node.id)
            for cid in src_pts.candidate_ids:
                obj = alias_env.object_store.get(cid)
                if obj:
                    value_type = obj.type_binding
                    break

        field_state.write_field_for_receiver(
            context_id=context_id,
            receiver_candidate_ids=receiver_pts.candidate_ids,
            field_name=field_name,
            points_to=value_pts,
            taint_state=taint,
            type_binding=value_type,
        )

    def _handle_expr_call(
        self,
        stmt: ast.Expr,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
    ) -> None:
        """Handle expression-level calls (no assignment target)."""
        # No alias/points-to side effects for standalone calls in this phase.
        # Taint tracking handles these calls separately via the propagator.
        pass

    def _handle_if(
        self,
        stmt: ast.If,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        counter: list[int],
    ) -> None:
        """Handle if/else branches with deterministic join."""
        # Fork environments for each branch
        then_env = alias_env.copy_for_branch()
        then_field = field_state.copy()
        self._process_statements(stmt.body, then_env, then_field, file_path, fn_qn, context_id, counter)

        if stmt.orelse:
            else_env = alias_env.copy_for_branch()
            else_field = field_state.copy()
            self._process_statements(stmt.orelse, else_env, else_field, file_path, fn_qn, context_id, counter)

            # Merge both branches
            merged_env = then_env.merge_branch(else_env)
            merged_field = then_field.merge(else_field)
        else:
            # Merge then-branch with the pre-if state
            merged_env = alias_env.merge_branch(then_env)
            merged_field = field_state.merge(then_field)

        # Apply merged state back
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
        value_node: ast.expr,
        alias_env: AliasEnvironment,
        field_state: FieldStateMap,
        file_path: str,
        fn_qn: str,
        context_id: str,
        line: int,
        col: int,
    ) -> PointsToSet:
        """Resolve the points-to set of a value expression."""
        # Variable reference
        if isinstance(value_node, ast.Name):
            return alias_env.get_points_to(value_node.id).copy()

        # Constructor call
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name):
            func_name = value_node.func.id
            if func_name[0].isupper():
                type_qn = self.repo_classes.get(func_name, func_name)
                tb = TypeBinding(
                    type_name=func_name,
                    qualified_type_name=type_qn,
                    confidence=TypeConfidence.KNOWN if func_name in self.repo_classes else TypeConfidence.LIKELY,
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

        # Field read
        if isinstance(value_node, ast.Attribute) and isinstance(value_node.value, ast.Name):
            receiver_pts = alias_env.get_points_to(value_node.value.id)
            if receiver_pts.candidate_ids:
                entry = field_state.read_field_merged(
                    context_id, receiver_pts.candidate_ids, value_node.attr
                )
                return entry.points_to.copy()

        return PointsToSet(is_unknown=True)

    def _resolve_annotation(self, annotation: ast.expr) -> Optional[str]:
        """Resolve a type annotation node to a type name string."""
        if isinstance(annotation, ast.Name):
            return annotation.id
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            return annotation.value
        if isinstance(annotation, ast.Attribute):
            parts = []
            node = annotation
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value  # type: ignore[assignment]
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        return None
