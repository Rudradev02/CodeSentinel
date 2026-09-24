"""Orchestrates static call graph construction across repository modules."""

import ast
from typing import Any, Callable, Optional

from analyzer.dataflow.callgraph.discovery import FunctionDiscovery
from analyzer.dataflow.callgraph.models import (
    CallEdge,
    CallGraph,
    CallResolutionType,
    FunctionDefinition,
    ResolutionStats,
    UnresolvedCall,
)
from analyzer.dataflow.callgraph.resolver import CallResolver
from analyzer.models.parse import ParsedFile
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class CallGraphBuilder:
    """Constructs a deterministic repository-wide static call graph."""

    def __init__(
        self,
        max_call_edges: int = 20000,
        max_functions_per_file: int = 200,
        max_total_functions: int = 5000,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.max_call_edges = max_call_edges
        self.max_functions_per_file = max_functions_per_file
        self.max_total_functions = max_total_functions
        self.is_cancelled = is_cancelled
        self.discovery = FunctionDiscovery(
            max_functions_per_file=max_functions_per_file,
            max_total_functions=max_total_functions,
            is_cancelled=is_cancelled,
        )

    def build_call_graph(
        self,
        parsed_files: list[ParsedFile],
        file_contents: dict[str, str],
        ast_cache: Optional[dict[str, Any]] = None,
    ) -> CallGraph:
        """Build the complete CallGraph from repository parsed files and source contents."""
        cache = ast_cache if ast_cache is not None else {}

        # 1. Discover all functions
        functions = self.discovery.discover_repository_functions(
            parsed_files=parsed_files,
            file_contents=file_contents,
            ast_cache=cache,
        )

        functions_by_file: dict[str, list[FunctionDefinition]] = {}
        for fn in functions:
            functions_by_file.setdefault(fn.file_path, []).append(fn)

        # 2. Build resolver
        resolver = CallResolver(functions)

        # Map parsed_files by relative path for quick import lookup
        parsed_file_map: dict[str, ParsedFile] = {
            pf.relative_path.replace("\\", "/"): pf for pf in parsed_files
        }

        edges: list[CallEdge] = []
        unresolved: list[UnresolvedCall] = []
        seen_edge_ids: set[str] = set()

        # 3. For each file and function, extract call expressions
        for pf in parsed_files:
            if self.is_cancelled and self.is_cancelled():
                from analyzer.models.errors import AnalysisCancelledError
                raise AnalysisCancelledError("Call graph construction was cancelled by user")

            if len(edges) >= self.max_call_edges:
                break

            rel_path = pf.relative_path.replace("\\", "/")
            content = file_contents.get(rel_path, "")
            if not content:
                continue

            file_fns = functions_by_file.get(rel_path, [])
            if not file_fns:
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
                self._extract_python_calls(
                    tree=tree,
                    file_path=rel_path,
                    functions=file_fns,
                    resolver=resolver,
                    imports=pf.imports,
                    edges=edges,
                    unresolved=unresolved,
                    seen_edge_ids=seen_edge_ids,
                )
            elif lang in ("JAVASCRIPT", "TYPESCRIPT"):
                self._extract_jsts_calls(
                    content=content,
                    file_path=rel_path,
                    language=lang,
                    functions=file_fns,
                    resolver=resolver,
                    imports=pf.imports,
                    edges=edges,
                    unresolved=unresolved,
                    seen_edge_ids=seen_edge_ids,
                )

        # 4. Compute resolution statistics
        total_calls = len(edges) + len(unresolved)
        res_local = sum(1 for e in edges if e.resolution_type == CallResolutionType.RESOLVED_LOCAL)
        res_import = sum(1 for e in edges if e.resolution_type == CallResolutionType.RESOLVED_IMPORT)
        res_rate = round(len(edges) / total_calls, 4) if total_calls > 0 else 0.0

        stats = ResolutionStats(
            total_call_sites=total_calls,
            resolved_local=res_local,
            resolved_import=res_import,
            unresolved=len(unresolved),
            resolution_rate=res_rate,
        )

        # Sort edges deterministically
        edges.sort(
            key=lambda e: (
                e.call_site_file,
                e.call_site_line,
                e.call_site_col,
                e.caller_qualified_name,
                e.callee_qualified_name or "",
            )
        )
        unresolved.sort(
            key=lambda u: (
                u.call_site_file,
                u.call_site_line,
                u.call_site_col,
                u.caller_qualified_name,
                u.callee_expression,
            )
        )

        fn_dict = {f.qualified_name: f for f in functions}
        return CallGraph(
            functions=fn_dict,
            edges=edges,
            unresolved_calls=unresolved,
            resolution_stats=stats,
        )

    def _extract_python_calls(
        self,
        tree: ast.AST,
        file_path: str,
        functions: list[FunctionDefinition],
        resolver: CallResolver,
        imports: list[Any],
        edges: list[CallEdge],
        unresolved: list[UnresolvedCall],
        seen_edge_ids: set[str],
    ) -> None:
        """Extract and resolve call sites in Python AST functions."""
        # Find which function encloses which line range
        for fn in functions:
            if len(edges) >= self.max_call_edges:
                break

            # Find matching AST node for this function
            target_node = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == fn.line_start and node.name == fn.name:
                    target_node = node
                    break

            if not target_node:
                continue

            # Walk target function body to find calls
            for node in ast.walk(target_node):
                if not isinstance(node, ast.Call):
                    continue

                if len(edges) >= self.max_call_edges:
                    break

                callee_expr = ""
                is_dyn = False
                try:
                    callee_expr = ast.unparse(node.func)
                except Exception:
                    callee_expr = "<call>"
                    is_dyn = True

                arg_count = len(node.args) + len(node.keywords)
                edge, unres = resolver.resolve_call(
                    caller=fn,
                    callee_expr=callee_expr,
                    line=node.lineno,
                    col=node.col_offset,
                    arg_count=arg_count,
                    is_dynamic=is_dyn,
                    imports=imports,
                    enclosing_class=fn.class_name,
                )

                if edge:
                    if edge.id not in seen_edge_ids:
                        seen_edge_ids.add(edge.id)
                        edges.append(edge)
                elif unres:
                    unresolved.append(unres)

    def _extract_jsts_calls(
        self,
        content: str,
        file_path: str,
        language: str,
        functions: list[FunctionDefinition],
        resolver: CallResolver,
        imports: list[Any],
        edges: list[CallEdge],
        unresolved: list[UnresolvedCall],
        seen_edge_ids: set[str],
    ) -> None:
        """Extract and resolve call sites in JavaScript/TypeScript CST functions."""
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
            return

        # Stack traversal to find call_expression nodes
        stack = [root_node]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                line_start, _, col_start, _ = get_node_line_and_col(n)
                # Find enclosing function by line range
                caller_fn = None
                for fn in functions:
                    if fn.line_start <= line_start <= fn.line_end:
                        caller_fn = fn
                        break

                if caller_fn:
                    fn_node = n.child_by_field_name("function")
                    callee_expr = node_text(fn_node, source_bytes).strip() if fn_node else ""
                    args_node = n.child_by_field_name("arguments")
                    arg_count = len(args_node.children) if args_node else 0

                    edge, unres = resolver.resolve_call(
                        caller=caller_fn,
                        callee_expr=callee_expr,
                        line=line_start,
                        col=col_start,
                        arg_count=arg_count,
                        imports=imports,
                        enclosing_class=caller_fn.class_name,
                    )
                    if edge:
                        if edge.id not in seen_edge_ids:
                            seen_edge_ids.add(edge.id)
                            edges.append(edge)
                    elif unres:
                        unresolved.append(unres)

            for c in reversed(n.children):
                stack.append(c)
