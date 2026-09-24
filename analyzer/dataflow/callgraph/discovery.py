"""Repository-wide static function discovery for Python and JavaScript/TypeScript."""

import ast
from pathlib import Path
from typing import Any, Callable, Optional

from analyzer.dataflow.callgraph.models import FunctionDefinition, ParameterDef
from analyzer.models.parse import ParsedFile
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


def _module_path_from_rel_path(rel_path: str) -> str:
    """Convert relative file path (e.g. 'utils/query.py') to dot-separated module path ('utils.query')."""
    p = Path(rel_path.replace("\\", "/"))
    # Strip extension
    parts = list(p.parts)
    if not parts:
        return ""
    last = parts[-1]
    if "." in last:
        last = last.rsplit(".", 1)[0]
    if last == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = last
    return ".".join(parts)


class FunctionDiscovery:
    """Discovers all function, method, and arrow function definitions across repository files."""

    def __init__(
        self,
        max_functions_per_file: int = 200,
        max_total_functions: int = 5000,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.max_functions_per_file = max_functions_per_file
        self.max_total_functions = max_total_functions
        self.is_cancelled = is_cancelled

    def discover_repository_functions(
        self,
        parsed_files: list[ParsedFile],
        file_contents: dict[str, str],
        ast_cache: Optional[dict[str, Any]] = None,
    ) -> list[FunctionDefinition]:
        """Extract all function definitions across all parsed repository files.
        
        Guarantees:
        - Bounded execution per file and repository
        - Deterministic ordering
        - Cooperative cancellation support
        """
        discovered: list[FunctionDefinition] = []
        cache = ast_cache if ast_cache is not None else {}

        # Sort files deterministically by relative path
        sorted_files = sorted(parsed_files, key=lambda pf: pf.relative_path.replace("\\", "/"))

        for pf in sorted_files:
            if self.is_cancelled and self.is_cancelled():
                from analyzer.models.errors import AnalysisCancelledError
                raise AnalysisCancelledError("Function discovery was cancelled by user")

            if len(discovered) >= self.max_total_functions:
                break

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
                file_fns = self.discover_python_functions(tree, rel_path)
            elif lang in ("JAVASCRIPT", "TYPESCRIPT"):
                file_fns = self.discover_jsts_functions(content, rel_path, lang)
            else:
                continue

            # Enforce max_functions_per_file bound
            if len(file_fns) > self.max_functions_per_file:
                file_fns = file_fns[: self.max_functions_per_file]

            # Add to discovered respecting repository cap
            remaining_cap = self.max_total_functions - len(discovered)
            discovered.extend(file_fns[:remaining_cap])

        # Sort deterministically
        discovered.sort(
            key=lambda fn: (
                fn.file_path.replace("\\", "/"),
                fn.line_start,
                fn.col_start,
                fn.qualified_name,
            )
        )
        return discovered

    def discover_python_functions(self, tree: ast.AST, file_path: str) -> list[FunctionDefinition]:
        """Extract functions and methods from a Python AST."""
        functions: list[FunctionDefinition] = []
        module_path = _module_path_from_rel_path(file_path)

        class PyVisitor(ast.NodeVisitor):
            def __init__(self, outer_self: "FunctionDiscovery"):
                self.outer = outer_self
                self.class_stack: list[str] = []

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._record_func(node, is_async=False)
                # Also visit inner nested functions
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._record_func(node, is_async=True)
                self.generic_visit(node)

            def _record_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
                if len(functions) >= self.outer.max_functions_per_file:
                    return

                is_method = len(self.class_stack) > 0
                class_name = self.class_stack[-1] if is_method else None

                # Build qualified name: module.Class.func or module.func
                prefix_parts = [p for p in [module_path] if p]
                if self.class_stack:
                    prefix_parts.extend(self.class_stack)
                prefix_parts.append(node.name)
                qualified_name = ".".join(prefix_parts)

                # Extract parameters
                parameters: list[ParameterDef] = []
                pos = 0
                # Positional / standard args
                all_args = node.args.args
                defaults = node.args.defaults
                num_defaults = len(defaults)
                num_args = len(all_args)

                for idx, arg in enumerate(all_args):
                    # Skip 'self' / 'cls' for methods if desired, but keep for index matching
                    has_default = idx >= (num_args - num_defaults)
                    type_str = None
                    if arg.annotation:
                        try:
                            type_str = ast.unparse(arg.annotation)
                        except Exception:
                            type_str = None
                    parameters.append(
                        ParameterDef(
                            name=arg.arg,
                            position=pos,
                            has_default=has_default,
                            type_hint=type_str,
                        )
                    )
                    pos += 1

                # Extract decorator names
                decorators: list[str] = []
                for dec in node.decorator_list:
                    try:
                        dec_str = ast.unparse(dec)
                        decorators.append(dec_str)
                    except Exception:
                        pass

                is_constructor = (node.name == "__init__" and is_method)
                end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
                fn_id = FunctionDefinition.create_deterministic_id(file_path, qualified_name, node.lineno)

                functions.append(
                    FunctionDefinition(
                        id=fn_id,
                        qualified_name=qualified_name,
                        file_path=file_path.replace("\\", "/"),
                        language="PYTHON",
                        name=node.name,
                        line_start=node.lineno,
                        line_end=end_line,
                        col_start=node.col_offset,
                        parameters=parameters,
                        is_method=is_method,
                        is_async=is_async,
                        is_constructor=is_constructor,
                        class_name=class_name,
                        module_path=module_path,
                        decorators=decorators,
                    )
                )

        visitor = PyVisitor(self)
        visitor.visit(tree)
        return functions

    def discover_jsts_functions(
        self,
        content: str,
        file_path: str,
        language: str = "JAVASCRIPT",
    ) -> list[FunctionDefinition]:
        """Extract functions, methods, and arrow functions from JavaScript/TypeScript CST."""
        functions: list[FunctionDefinition] = []
        module_path = _module_path_from_rel_path(file_path)
        source_bytes = content.encode("utf-8", errors="replace")

        try:
            if language == "TYPESCRIPT":
                from tree_sitter import Language, Parser
                import tree_sitter_typescript
                ts_lang = Language(tree_sitter_typescript.language_typescript())
                parser = Parser(ts_lang)
            else:
                from tree_sitter import Language, Parser
                import tree_sitter_javascript
                js_lang = Language(tree_sitter_javascript.language())
                parser = Parser(js_lang)

            tree = parser.parse(source_bytes)
            root_node = tree.root_node
        except Exception:
            return []

        # Traverse AST maintaining enclosing class context
        # Stack entries: (node, enclosing_class_name)
        stack: list[tuple[Any, Optional[str]]] = [(root_node, None)]

        while stack:
            if self.is_cancelled and self.is_cancelled():
                from analyzer.models.errors import AnalysisCancelledError
                raise AnalysisCancelledError("Function discovery was cancelled by user")

            node, enclosing_class = stack.pop()

            if len(functions) >= self.max_functions_per_file:
                break

            current_class = enclosing_class
            if node.type in ("class_declaration", "class"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    current_class = node_text(name_node, source_bytes).strip()

            if node.type in ("function_declaration", "arrow_function", "function_expression", "method_definition"):
                fn_name = ""
                is_method = node.type == "method_definition" or (current_class is not None)
                is_constructor = False

                if node.type == "method_definition":
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        fn_name = node_text(name_node, source_bytes).strip()
                    if fn_name == "constructor":
                        is_constructor = True
                elif node.type == "function_declaration":
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        fn_name = node_text(name_node, source_bytes).strip()
                elif node.type in ("arrow_function", "function_expression"):
                    # Check if assigned to variable: const myFunc = () => ...
                    parent = node.parent
                    if parent and parent.type == "variable_declarator":
                        id_node = parent.child_by_field_name("name")
                        if id_node:
                            fn_name = node_text(id_node, source_bytes).strip()

                if not fn_name:
                    fn_name = "<anonymous>"

                line_start, col_start = get_node_line_and_col(node)
                line_end = node.end_point[0] + 1

                # Construct qualified name
                prefix_parts = [p for p in [module_path] if p]
                if current_class:
                    prefix_parts.append(current_class)
                prefix_parts.append(fn_name)
                qualified_name = ".".join(prefix_parts)

                # Extract parameters
                parameters: list[ParameterDef] = []
                params_node = node.child_by_field_name("parameters")
                if params_node:
                    pos = 0
                    for c in params_node.children:
                        if c.type in ("identifier", "required_parameter", "optional_parameter"):
                            p_name = node_text(c, source_bytes).strip().split(":")[0].strip()
                            parameters.append(ParameterDef(name=p_name, position=pos))
                            pos += 1

                is_async = any(c.type == "async" for c in node.children)
                fn_id = FunctionDefinition.create_deterministic_id(file_path, qualified_name, line_start)

                functions.append(
                    FunctionDefinition(
                        id=fn_id,
                        qualified_name=qualified_name,
                        file_path=file_path.replace("\\", "/"),
                        language=language,
                        name=fn_name,
                        line_start=line_start,
                        line_end=line_end,
                        col_start=col_start,
                        parameters=parameters,
                        is_method=is_method,
                        is_async=is_async,
                        is_constructor=is_constructor,
                        class_name=current_class,
                        module_path=module_path,
                    )
                )

            # Push children to stack
            for child in reversed(node.children):
                stack.append((child, current_class))

        return functions
