"""Static type extractor for JavaScript and TypeScript CSTs using Tree-sitter (Phase 16)."""

from typing import Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.types.models import (
    TypeBinding,
    TypeConfidence,
    TypeEnvironment,
    TypeOrigin,
)
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class JSTSTypeExtractor:
    """Extracts conservative type bindings from JS/TS syntax CSTs using repository evidence."""

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
        fn_node: Node,
        source_bytes: bytes,
        file_path: str,
        enclosing_class: Optional[str] = None,
    ) -> TypeEnvironment:
        """Infer type bindings within a JS/TS function or method scope."""
        self.check_cancellation()
        env = TypeEnvironment()
        step_count = 0

        # 1. Bind 'this' if inside a class
        if enclosing_class:
            qn = self.repo_classes.get(enclosing_class, enclosing_class)
            line, _, _, _ = get_node_line_and_col(fn_node)
            env.set_type(
                "this",
                TypeBinding(
                    type_name=enclosing_class,
                    qualified_type_name=qn,
                    confidence=TypeConfidence.KNOWN,
                    origin=TypeOrigin.SELF_RECEIVER,
                    source_file=file_path,
                    line=line,
                ),
            )

        # 2. Extract parameter type annotations (TypeScript)
        params_node = fn_node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                step_count += 1
                if step_count > self.max_inference_steps:
                    break
                if child.type in ("required_parameter", "optional_parameter"):
                    pattern = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    type_node = child.child_by_field_name("type")
                    if pattern and type_node:
                        param_name = node_text(pattern, source_bytes).strip()
                        raw_type = node_text(type_node, source_bytes).strip().lstrip(":").strip()
                        if param_name and raw_type:
                            qn = self.repo_classes.get(raw_type, raw_type)
                            is_repo = raw_type in self.repo_classes
                            line, _, col, _ = get_node_line_and_col(child)
                            env.set_type(
                                param_name,
                                TypeBinding(
                                    type_name=raw_type,
                                    qualified_type_name=qn,
                                    confidence=TypeConfidence.KNOWN if is_repo else TypeConfidence.UNKNOWN,
                                    origin=TypeOrigin.TYPE_ANNOTATION,
                                    source_file=file_path,
                                    line=line,
                                    col=col,
                                ),
                            )

        # 3. Traverse body statements
        body_node = fn_node.child_by_field_name("body")
        if not body_node:
            for child in fn_node.children:
                if child.type in ("statement_block", "expression_statement"):
                    body_node = child
                    break

        if body_node:
            for stmt in body_node.children:
                self.check_cancellation()
                step_count += 1
                if step_count > self.max_inference_steps:
                    break

                # Variable declarations: const x = new ClassName() or const a = b
                if stmt.type in ("lexical_declaration", "variable_declaration"):
                    for decl in stmt.children:
                        if decl.type == "variable_declarator":
                            name_node = decl.child_by_field_name("name")
                            val_node = decl.child_by_field_name("value")
                            type_node = decl.child_by_field_name("type")
                            if not name_node:
                                continue
                            var_name = node_text(name_node, source_bytes).strip()
                            line, _, col, _ = get_node_line_and_col(decl)

                            # Explicit TS type annotation: const x: UserRepo = ...
                            if type_node:
                                raw_type = node_text(type_node, source_bytes).strip().lstrip(":").strip()
                                qn = self.repo_classes.get(raw_type, raw_type)
                                is_repo = raw_type in self.repo_classes
                                env.set_type(
                                    var_name,
                                    TypeBinding(
                                        type_name=raw_type,
                                        qualified_type_name=qn,
                                        confidence=TypeConfidence.KNOWN if is_repo else TypeConfidence.UNKNOWN,
                                        origin=TypeOrigin.TYPE_ANNOTATION,
                                        source_file=file_path,
                                        line=line,
                                        col=col,
                                    ),
                                )
                                continue

                            # Value is new ClassName()
                            if val_node and val_node.type == "new_expression":
                                constructor_node = val_node.child_by_field_name("constructor")
                                if constructor_node:
                                    cls_name = node_text(constructor_node, source_bytes).strip()
                                    qn = self.repo_classes.get(cls_name, cls_name)
                                    is_repo = cls_name in self.repo_classes
                                    env.set_type(
                                        var_name,
                                        TypeBinding(
                                            type_name=cls_name,
                                            qualified_type_name=qn,
                                            confidence=TypeConfidence.KNOWN if is_repo else TypeConfidence.UNKNOWN,
                                            origin=TypeOrigin.CONSTRUCTOR,
                                            source_file=file_path,
                                            line=line,
                                            col=col,
                                        ),
                                    )
                                continue

                            # Value is local alias: const a = b
                            if val_node and val_node.type == "identifier":
                                ref_name = node_text(val_node, source_bytes).strip()
                                source_binding = env.get_type(ref_name)
                                if source_binding:
                                    env.set_type(
                                        var_name,
                                        TypeBinding(
                                            type_name=source_binding.type_name,
                                            qualified_type_name=source_binding.qualified_type_name,
                                            confidence=source_binding.confidence,
                                            origin=TypeOrigin.ALIAS,
                                            source_file=file_path,
                                            line=line,
                                            col=col,
                                        ),
                                    )

        return env
