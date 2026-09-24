"""Static type extractor for Python ASTs (Phase 16)."""

import ast
from typing import Any, Callable, Optional, Set

from analyzer.dataflow.types.models import (
    TypeBinding,
    TypeConfidence,
    TypeEnvironment,
    TypeOrigin,
)
from analyzer.models.parse import ImportCategory, ImportStatement


class PythonTypeExtractor:
    """Extracts conservative type bindings from Python ASTs using repository-local evidence."""

    def __init__(
        self,
        repo_classes: Optional[dict[str, str]] = None,  # short_name -> qualified_name
        max_inference_steps: int = 200,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.repo_classes = repo_classes or {}
        self.max_inference_steps = max_inference_steps
        self.is_cancelled = is_cancelled

    def check_cancellation(self) -> None:
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Type inference was cancelled by user")

    def extract_function_types(
        self,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        imports: Optional[list[ImportStatement]] = None,
        enclosing_class: Optional[str] = None,
    ) -> TypeEnvironment:
        """Infer type bindings within a single function body."""
        self.check_cancellation()
        env = TypeEnvironment()
        norm_imports = imports or []
        step_count = 0

        # Map imported names to their targets
        imported_symbols: dict[str, str] = {}
        for imp in norm_imports:
            if imp.dependency_category != ImportCategory.EXTERNAL:
                for name in imp.imported_names:
                    imported_symbols[name] = imp.resolved_path or imp.source_module

        # 1. Bind 'self' or 'cls' if inside a class
        if enclosing_class:
            qn = self.repo_classes.get(enclosing_class, enclosing_class)
            env.set_type(
                "self",
                TypeBinding(
                    type_name=enclosing_class,
                    qualified_type_name=qn,
                    confidence=TypeConfidence.KNOWN,
                    origin=TypeOrigin.SELF_RECEIVER,
                    source_file=file_path,
                    line=fn_node.lineno,
                ),
            )

        # 2. Extract parameter type annotations
        for arg in fn_node.args.args:
            step_count += 1
            if step_count > self.max_inference_steps:
                break
            if arg.arg in ("self", "cls"):
                continue
            if arg.annotation:
                type_name = self._resolve_annotation_name(arg.annotation)
                if type_name:
                    confidence = (
                        TypeConfidence.KNOWN
                        if type_name in self.repo_classes or type_name in imported_symbols
                        else TypeConfidence.UNKNOWN
                    )
                    qn = self.repo_classes.get(type_name, type_name)
                    env.set_type(
                        arg.arg,
                        TypeBinding(
                            type_name=type_name,
                            qualified_type_name=qn,
                            confidence=confidence,
                            origin=TypeOrigin.TYPE_ANNOTATION,
                            source_file=file_path,
                            line=getattr(arg, "lineno", fn_node.lineno),
                        ),
                    )

        # 3. Traverse body statements
        for stmt in fn_node.body:
            self.check_cancellation()
            step_count += 1
            if step_count > self.max_inference_steps:
                break

            # AnnAssign: x: ClassName = ... or self.x: ClassName = ...
            if isinstance(stmt, ast.AnnAssign):
                annot_name = self._resolve_annotation_name(stmt.annotation)
                if isinstance(stmt.target, ast.Name) and annot_name:
                    qn = self.repo_classes.get(annot_name, annot_name)
                    confidence = (
                        TypeConfidence.KNOWN
                        if annot_name in self.repo_classes or annot_name in imported_symbols
                        else TypeConfidence.UNKNOWN
                    )
                    env.set_type(
                        stmt.target.id,
                        TypeBinding(
                            type_name=annot_name,
                            qualified_type_name=qn,
                            confidence=confidence,
                            origin=TypeOrigin.TYPE_ANNOTATION,
                            source_file=file_path,
                            line=stmt.lineno,
                        ),
                    )
                elif (
                    isinstance(stmt.target, ast.Attribute)
                    and isinstance(stmt.target.value, ast.Name)
                    and stmt.target.value.id == "self"
                    and annot_name
                ):
                    qn = self.repo_classes.get(annot_name, annot_name)
                    confidence = (
                        TypeConfidence.KNOWN
                        if annot_name in self.repo_classes or annot_name in imported_symbols
                        else TypeConfidence.UNKNOWN
                    )
                    env.set_field_type(
                        "self",
                        stmt.target.attr,
                        TypeBinding(
                            type_name=annot_name,
                            qualified_type_name=qn,
                            confidence=confidence,
                            origin=TypeOrigin.TYPE_ANNOTATION,
                            source_file=file_path,
                            line=stmt.lineno,
                        ),
                    )

            # Assign: x = expr or self.x = expr
            elif isinstance(stmt, ast.Assign) and stmt.value:
                rhs_binding = self._infer_expression_type(
                    stmt.value,
                    env,
                    file_path,
                    stmt.lineno,
                    imported_symbols,
                )
                if not rhs_binding:
                    continue

                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env.set_type(target.id, rhs_binding)
                    elif (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        field_binding = TypeBinding(
                            type_name=rhs_binding.type_name,
                            qualified_type_name=rhs_binding.qualified_type_name,
                            confidence=rhs_binding.confidence,
                            origin=TypeOrigin.FIELD_ASSIGNMENT,
                            source_file=file_path,
                            line=stmt.lineno,
                            col=target.col_offset,
                        )
                        env.set_field_type("self", target.attr, field_binding)

        return env

    def _infer_expression_type(
        self,
        node: ast.expr,
        env: TypeEnvironment,
        file_path: str,
        line: int,
        imported_symbols: dict[str, str],
    ) -> Optional[TypeBinding]:
        """Infer type of RHS expression."""
        # 1. Constructor call: x = ClassName(...)
        if isinstance(node, ast.Call):
            func_name = self._resolve_call_func_name(node.func)
            if func_name:
                is_repo = func_name in self.repo_classes or func_name in imported_symbols
                qn = self.repo_classes.get(func_name, func_name)
                return TypeBinding(
                    type_name=func_name,
                    qualified_type_name=qn,
                    confidence=TypeConfidence.KNOWN if is_repo else TypeConfidence.UNKNOWN,
                    origin=TypeOrigin.CONSTRUCTOR,
                    source_file=file_path,
                    line=line,
                )

        # 2. Local variable alias: a = b
        if isinstance(node, ast.Name):
            source_binding = env.get_type(node.id)
            if source_binding:
                return TypeBinding(
                    type_name=source_binding.type_name,
                    qualified_type_name=source_binding.qualified_type_name,
                    confidence=source_binding.confidence,
                    origin=TypeOrigin.ALIAS,
                    source_file=file_path,
                    line=line,
                )

        # 3. Field access: a = self.db
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            field_binding = env.get_field_type("self", node.attr)
            if field_binding:
                return TypeBinding(
                    type_name=field_binding.type_name,
                    qualified_type_name=field_binding.qualified_type_name,
                    confidence=field_binding.confidence,
                    origin=TypeOrigin.ALIAS,
                    source_file=file_path,
                    line=line,
                )

        return None

    def _resolve_annotation_name(self, node: ast.expr) -> Optional[str]:
        """Extract string representation of an annotation node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _resolve_call_func_name(self, node: ast.expr) -> Optional[str]:
        """Extract called function name from AST Call.func."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None
