"""Interprocedural taint propagator executing cross-function data-flow analysis (Phase 16)."""

import ast
import hashlib
from typing import Any, Callable, Optional, Set
import uuid
from tree_sitter import Node

from analyzer.dataflow.callgraph.context_manager import ContextManager
from analyzer.dataflow.callgraph.context_summarizer import ContextSummaryManager, ContextualFunctionSummary
from analyzer.dataflow.callgraph.models import (
    CallChainStep,
    CallGraph,
    FunctionDefinition,
    FunctionSummary,
    InterproceduralTaintPath,
)
from analyzer.dataflow.callgraph.resolver import CallResolver
from analyzer.dataflow.callgraph.type_resolver import TypeAwareCallResolver
from analyzer.dataflow.js_visitor import JSDataFlowAnalyzer
from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.dataflow.symbol import DefinitionKind, Scope, ScopeKind
from analyzer.dataflow.taint.models import SinkCategory, TaintPath, TaintSource, TaintState, TaintStep
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry
from analyzer.dataflow.types.models import CallContext, ConstantBool, TypeConfidence, TypeEnvironment
from analyzer.dataflow.types.python_type_extractor import PythonTypeExtractor
from analyzer.dataflow.types.jsts_type_extractor import JSTSTypeExtractor
from analyzer.models.parse import ParsedFile
from analyzer.rules.js_ast_helper import get_node_line_and_col, node_text


class InterproceduralTaintPropagator:
    """Propagates taint across function call boundaries with type awareness and context sensitivity."""

    def __init__(
        self,
        call_graph: CallGraph,
        summaries: dict[str, FunctionSummary],
        registry: Optional[TaintRegistry] = None,
        max_call_depth: int = 5,
        max_path_count: int = 50,
        max_evidence_steps: int = 30,
        is_cancelled: Optional[Callable[[], bool]] = None,
        disable_type_inference: bool = False,
        disable_context_sensitivity: bool = False,
        max_k: int = 2,
        max_contexts_per_function: int = 8,
        max_total_contexts: int = 1000,
    ):
        self.call_graph = call_graph
        self.summaries = summaries
        self.registry = registry or TaintRegistry(load_defaults=True)
        self.max_call_depth = max_call_depth
        self.max_path_count = max_path_count
        self.max_evidence_steps = max_evidence_steps
        self.is_cancelled = is_cancelled
        self.disable_type_inference = disable_type_inference
        self.disable_context_sensitivity = disable_context_sensitivity

        self.resolver = CallResolver(list(call_graph.functions.values()))
        self.type_resolver = (
            self.resolver
            if disable_type_inference
            else TypeAwareCallResolver(list(call_graph.functions.values()), base_resolver=self.resolver)
        )
        self.context_manager = ContextManager(
            max_k=max_k,
            max_contexts_per_function=max_contexts_per_function,
            max_total_contexts=max_total_contexts,
        )
        self.context_summary_manager = ContextSummaryManager(
            base_summaries=summaries,
            registry=self.registry,
            is_cancelled=is_cancelled,
        )

        # Build repository class map (short_name -> qualified_name)
        self.repo_classes: dict[str, str] = {}
        for f in call_graph.functions.values():
            if f.class_name:
                self.repo_classes[f.class_name] = f"{f.module_path}.{f.class_name}" if f.module_path else f.class_name

        self.python_type_extractor = PythonTypeExtractor(repo_classes=self.repo_classes, is_cancelled=is_cancelled)
        self.jsts_type_extractor = JSTSTypeExtractor(repo_classes=self.repo_classes, is_cancelled=is_cancelled)

        # Statistics
        self.type_aware_edges_count = 0
        self.types_inferred_count = 0
        self.ambiguous_receivers_count = 0
        self.confidence_distribution = {"KNOWN": 0, "LIKELY": 0, "AMBIGUOUS": 0, "UNKNOWN": 0}

    def check_cancellation(self) -> None:
        """Cooperative cancellation checkpoint."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Interprocedural analysis was cancelled by user")

    def get_semantic_summary(self) -> dict[str, Any]:
        """Return Phase 16 semantic metrics for serialization into call_graph_summary."""
        return {
            "type_resolution": {
                "types_inferred": self.types_inferred_count,
                "type_aware_edges": self.type_aware_edges_count,
                "ambiguous_receivers": self.ambiguous_receivers_count,
                "confidence_distribution": self.confidence_distribution,
            },
            "context_sensitivity": {
                "total_contexts": self.context_manager.total_contexts_count,
                "max_depth_reached": min(self.max_call_depth, 2),
                "contexts_truncated": len(self.context_manager.truncation_reasons),
                "truncation_reasons": sorted(list(self.context_manager.truncation_reasons)),
            },
        }

    def analyze_repository(
        self,
        parsed_files: list[ParsedFile],
        file_contents: dict[str, str],
        ast_cache: Optional[dict[str, Any]] = None,
    ) -> list[InterproceduralTaintPath]:
        """Traverse functions and detect cross-function taint flows from sources to sinks."""
        self.check_cancellation()
        cache = ast_cache if ast_cache is not None else {}
        paths: list[InterproceduralTaintPath] = []
        seen_path_keys: set[str] = set()

        # Sort functions deterministically
        sorted_fns = sorted(
            self.call_graph.functions.values(),
            key=lambda fn: (
                fn.file_path.replace("\\", "/"),
                fn.line_start,
                fn.col_start,
                fn.qualified_name,
            ),
        )

        for fn_def in sorted_fns:
            self.check_cancellation()
            if len(paths) >= self.max_path_count:
                break

            content = file_contents.get(fn_def.file_path, "")
            if not content:
                continue

            lang = fn_def.language.upper()
            if lang == "PYTHON":
                tree = cache.get(fn_def.file_path)
                if tree is None or not isinstance(tree, ast.AST):
                    try:
                        tree = ast.parse(content, filename=fn_def.file_path)
                        cache[fn_def.file_path] = tree
                    except SyntaxError:
                        continue
                fn_paths = self._analyze_python_function(fn_def, tree, content)
            elif lang in ("JAVASCRIPT", "TYPESCRIPT"):
                root_node = cache.get(fn_def.file_path)
                if root_node is None:
                    from analyzer.parsing.javascript_parser import JavaScriptParser
                    from analyzer.parsing.typescript_parser import TypeScriptParser
                    p = TypeScriptParser() if lang == "TYPESCRIPT" else JavaScriptParser()
                    source_bytes = content.encode("utf-8", errors="replace")
                    try:
                        tree = p.ts_parser.parse(source_bytes) if lang == "TYPESCRIPT" else p.parser.parse(source_bytes)
                        root_node = tree.root_node
                        cache[fn_def.file_path] = root_node
                    except Exception:
                        continue
                if root_node is None:
                    continue
                fn_paths = self._analyze_jsts_function(fn_def, root_node, content.encode("utf-8", errors="replace"))
            else:
                continue

            for p in fn_paths:
                chain_sig = ":".join(f"{s.caller_function}->{s.callee_function}" for s in p.call_chain)
                key = f"{p.source.get('file_path')}:{p.source.get('line')}:{p.sink.get('file_path')}:{p.sink.get('line')}:{p.category.value}:{chain_sig}"
                if key not in seen_path_keys:
                    seen_path_keys.add(key)
                    paths.append(p)
                    if len(paths) >= self.max_path_count:
                        break

        # Deterministic sort
        paths.sort(
            key=lambda p: (
                p.source.get("file_path", ""),
                p.source.get("line", 0),
                p.sink.get("file_path", ""),
                p.sink.get("line", 0),
                p.category.value,
            )
        )
        return paths

    def _analyze_python_function(
        self,
        fn_def: FunctionDefinition,
        tree: ast.AST,
        file_content: str,
    ) -> list[InterproceduralTaintPath]:
        """Analyze a Python function scope for interprocedural taint flows."""
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
            return []

        base_analyzer = PythonDataFlowAnalyzer(registry=self.registry, is_cancelled=self.is_cancelled)
        detected_paths: list[InterproceduralTaintPath] = []

        # Infer local types
        type_env: Optional[TypeEnvironment] = None
        if not self.disable_type_inference:
            type_env = self.python_type_extractor.extract_function_types(
                fn_node, fn_def.file_path, enclosing_class=fn_def.class_name
            )
            self.types_inferred_count += len(type_env.bindings)

        # Local tracking state
        var_sources: dict[str, dict[str, Any]] = {}
        var_call_chains: dict[str, list[CallChainStep]] = {}
        var_states: dict[str, TaintState] = {}
        var_sanitizers: dict[str, list[str]] = {}

        # Active call stack for recursion guard
        active_call_stack: set[tuple[str, str]] = set()

        statements = fn_node.body[:500]

        for stmt in statements:
            self.check_cancellation()

            # 1. Assignment: x = expr
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value_node = stmt.value if isinstance(stmt, ast.Assign) else stmt.value
                if value_node is None:
                    continue
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)] if isinstance(stmt, ast.Assign) else ([stmt.target.id] if isinstance(stmt.target, ast.Name) else [])
                if not targets:
                    continue
                target_var = targets[0]
                raw_expr = ast.unparse(value_node) if hasattr(ast, "unparse") else "<expr>"

                # Check if RHS is a direct source
                source = base_analyzer._extract_source(value_node) or base_analyzer._find_any_source(value_node)
                if source:
                    src_dict = {
                        "source_id": source.source_id,
                        "file_path": fn_def.file_path,
                        "line": stmt.lineno,
                        "column": stmt.col_offset,
                        "expression": raw_expr,
                        "category": source.category.value,
                    }
                    var_sources[target_var] = src_dict
                    var_call_chains[target_var] = []
                    var_states[target_var] = TaintState.TAINTED
                    var_sanitizers[target_var] = []
                    continue

                # Check if RHS is a function call
                if isinstance(value_node, ast.Call):
                    callee_name = base_analyzer._get_call_name(value_node)
                    # Check if any argument is tainted
                    for arg_idx, arg_node in enumerate(value_node.args):
                        arg_names = base_analyzer._extract_names(arg_node)
                        tainted_arg = next(
                            (name for name in arg_names if var_states.get(name) == TaintState.TAINTED),
                            None,
                        )
                        if not tainted_arg:
                            continue

                        # Resolve callee using type-aware resolver
                        resolved_edge = None
                        if isinstance(self.type_resolver, TypeAwareCallResolver):
                            resolved_edge, _ = self.type_resolver.resolve_call(
                                caller=fn_def,
                                callee_expr=callee_name,
                                line=stmt.lineno,
                                col=stmt.col_offset,
                                arg_count=len(value_node.args),
                                type_env=type_env,
                                enclosing_class=fn_def.class_name,
                            )
                        target_callee_qn = (
                            resolved_edge.callee_qualified_name
                            if resolved_edge and resolved_edge.callee_qualified_name
                            else callee_name
                        )

                        if resolved_edge and resolved_edge.receiver_confidence:
                            self.type_aware_edges_count += 1
                            self.confidence_distribution[resolved_edge.receiver_confidence] = (
                                self.confidence_distribution.get(resolved_edge.receiver_confidence, 0) + 1
                            )

                        # Recursion guard check
                        active_pair = (fn_def.qualified_name, target_callee_qn)
                        if active_pair in active_call_stack:
                            continue
                        active_call_stack.add(active_pair)

                        # Context management & constant-aware branch refinement
                        const_args: dict[int, ConstantBool] = {}
                        for c_idx, c_arg in enumerate(value_node.args):
                            if isinstance(c_arg, ast.Constant) and isinstance(c_arg.value, bool):
                                const_args[c_idx] = ConstantBool.TRUE if c_arg.value else ConstantBool.FALSE

                        call_site_id = f"{fn_def.file_path}:{stmt.lineno}:{stmt.col_offset}"
                        if not self.disable_context_sensitivity:
                            ctx, _ = self.context_manager.get_or_create_context(
                                callee_qn=target_callee_qn,
                                parent=CallContext.create_root_context(),
                                call_site_id=call_site_id,
                                arg_taints=[
                                    any(var_states.get(n) == TaintState.TAINTED for n in base_analyzer._extract_names(a))
                                    for a in value_node.args
                                ],
                                constant_args=const_args,
                                receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                            )
                            ctx_id = ctx.context_id
                        else:
                            ctx_id = "ROOT"

                        callee_summary = self.context_summary_manager.get_summary(
                            target_callee_qn, ctx_id
                        ) or self._resolve_callee_summary(target_callee_qn, fn_def.file_path)
                        if not callee_summary:
                            continue

                        callee_param_name = (
                            callee_summary.parameters[arg_idx].name
                            if hasattr(callee_summary, "parameters") and arg_idx < len(callee_summary.parameters)
                            else f"arg_{arg_idx}"
                        )

                        # Check if callee reaches a sink internally
                        for sink_inv in callee_summary.sink_invocations:
                            if sink_inv.receiving_param_index == arg_idx:
                                step = CallChainStep(
                                    caller_function=fn_def.qualified_name,
                                    callee_function=callee_summary.qualified_name,
                                    caller_file=fn_def.file_path,
                                    callee_file=getattr(callee_summary, "file_path", fn_def.file_path),
                                    call_site_line=stmt.lineno,
                                    call_site_col=stmt.col_offset,
                                    argument_index=arg_idx,
                                    callee_param_name=callee_param_name,
                                    taint_action="REACHES_SINK",
                                    receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                    receiver_confidence=resolved_edge.receiver_confidence if resolved_edge else None,
                                    context_id=ctx_id,
                                )
                                chain = var_call_chains.get(tainted_arg, []) + [step]
                                sink_dict = {
                                    "sink_id": sink_inv.sink_id,
                                    "file_path": getattr(callee_summary, "file_path", fn_def.file_path),
                                    "line": sink_inv.line,
                                    "column": 0,
                                    "expression": f"{callee_name}()",
                                }
                                path = self._build_path(
                                    source_dict=var_sources[tainted_arg],
                                    call_chain=chain,
                                    sink_dict=sink_dict,
                                    category=sink_inv.sink_category,
                                )
                                detected_paths.append(path)

                        # Check if callee transfers taint to return
                        for transfer in callee_summary.taint_transfers:
                            if transfer.from_param_index == arg_idx and transfer.to_return:
                                step = CallChainStep(
                                    caller_function=fn_def.qualified_name,
                                    callee_function=callee_summary.qualified_name,
                                    caller_file=fn_def.file_path,
                                    callee_file=getattr(callee_summary, "file_path", fn_def.file_path),
                                    call_site_line=stmt.lineno,
                                    call_site_col=stmt.col_offset,
                                    argument_index=arg_idx,
                                    callee_param_name=callee_param_name,
                                    taint_action="PROPAGATE_THROUGH",
                                    receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                    receiver_confidence=resolved_edge.receiver_confidence if resolved_edge else None,
                                    context_id=ctx_id,
                                )
                                if len(var_call_chains.get(tainted_arg, [])) < self.max_call_depth:
                                    var_call_chains[target_var] = var_call_chains.get(tainted_arg, []) + [step]
                                    var_sources[target_var] = var_sources[tainted_arg]
                                    if transfer.sanitized_by:
                                        var_states[target_var] = TaintState.SANITIZED
                                        var_sanitizers[target_var] = [transfer.sanitized_by]
                                    else:
                                        var_states[target_var] = TaintState.TAINTED
                                        var_sanitizers[target_var] = []
                    continue

                # Standard variable propagation (y = x or y = f"SELECT {x}")
                names = base_analyzer._extract_names(value_node)
                tainted_name = next((n for n in names if var_states.get(n) == TaintState.TAINTED), None)
                if tainted_name:
                    var_states[target_var] = TaintState.TAINTED
                    var_sources[target_var] = var_sources[tainted_name]
                    var_call_chains[target_var] = list(var_call_chains.get(tainted_name, []))
                    var_sanitizers[target_var] = list(var_sanitizers.get(tainted_name, []))

            # 2. Expression statements: cursor.execute(query) or service.update_user(...)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_node = stmt.value
                callee_name = base_analyzer._get_call_name(call_node)
                receiver_name = base_analyzer._get_receiver_name(call_node)

                # Check if call is a known sink
                matched_sink = self.registry.find_matching_sink(
                    language="PYTHON",
                    callee_name=callee_name,
                    receiver_name=receiver_name,
                )
                if matched_sink:
                    for v_idx in matched_sink.vulnerable_arg_indices:
                        if v_idx < len(call_node.args):
                            arg_names = base_analyzer._extract_names(call_node.args[v_idx])
                            tainted_arg = next(
                                (n for n in arg_names if var_states.get(n) == TaintState.TAINTED),
                                None,
                            )
                            if tainted_arg:
                                chain = var_call_chains.get(tainted_arg, [])
                                if chain and len(chain) >= 1:
                                    raw_sink = ast.unparse(call_node) if hasattr(ast, "unparse") else callee_name
                                    sink_dict = {
                                        "sink_id": matched_sink.sink_id,
                                        "file_path": fn_def.file_path,
                                        "line": call_node.lineno,
                                        "column": call_node.col_offset,
                                        "expression": raw_sink,
                                    }
                                    path = self._build_path(
                                        source_dict=var_sources[tainted_arg],
                                        call_chain=chain,
                                        sink_dict=sink_dict,
                                        category=matched_sink.category,
                                    )
                                    detected_paths.append(path)
                else:
                    # Could call a function/method that executes a sink internally
                    for arg_idx, arg_node in enumerate(call_node.args):
                        arg_names = base_analyzer._extract_names(arg_node)
                        tainted_arg = next(
                            (n for n in arg_names if var_states.get(n) == TaintState.TAINTED),
                            None,
                        )
                        if not tainted_arg:
                            continue

                        # Resolve via type-aware resolver
                        resolved_edge = None
                        if isinstance(self.type_resolver, TypeAwareCallResolver):
                            resolved_edge, _ = self.type_resolver.resolve_call(
                                caller=fn_def,
                                callee_expr=callee_name,
                                line=call_node.lineno,
                                col=call_node.col_offset,
                                arg_count=len(call_node.args),
                                type_env=type_env,
                                enclosing_class=fn_def.class_name,
                            )
                        target_callee_qn = (
                            resolved_edge.callee_qualified_name
                            if resolved_edge and resolved_edge.callee_qualified_name
                            else callee_name
                        )

                        if resolved_edge and resolved_edge.receiver_confidence:
                            self.type_aware_edges_count += 1
                            self.confidence_distribution[resolved_edge.receiver_confidence] = (
                                self.confidence_distribution.get(resolved_edge.receiver_confidence, 0) + 1
                            )

                        active_pair = (fn_def.qualified_name, target_callee_qn)
                        if active_pair in active_call_stack:
                            continue
                        active_call_stack.add(active_pair)

                        call_site_id = f"{fn_def.file_path}:{call_node.lineno}:{call_node.col_offset}"
                        if not self.disable_context_sensitivity:
                            ctx, _ = self.context_manager.get_or_create_context(
                                callee_qn=target_callee_qn,
                                parent=CallContext.create_root_context(),
                                call_site_id=call_site_id,
                                arg_taints=[
                                    any(var_states.get(n) == TaintState.TAINTED for n in base_analyzer._extract_names(a))
                                    for a in call_node.args
                                ],
                                receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                            )
                            ctx_id = ctx.context_id
                        else:
                            ctx_id = "ROOT"

                        callee_summary = self.context_summary_manager.get_summary(
                            target_callee_qn, ctx_id
                        ) or self._resolve_callee_summary(target_callee_qn, fn_def.file_path)
                        if not callee_summary:
                            continue
                        for sink_inv in callee_summary.sink_invocations:
                            if sink_inv.receiving_param_index == arg_idx:
                                callee_param_name = (
                                    callee_summary.parameters[arg_idx].name
                                    if hasattr(callee_summary, "parameters") and arg_idx < len(callee_summary.parameters)
                                    else f"arg_{arg_idx}"
                                )
                                step = CallChainStep(
                                    caller_function=fn_def.qualified_name,
                                    callee_function=callee_summary.qualified_name,
                                    caller_file=fn_def.file_path,
                                    callee_file=getattr(callee_summary, "file_path", fn_def.file_path),
                                    call_site_line=call_node.lineno,
                                    call_site_col=call_node.col_offset,
                                    argument_index=arg_idx,
                                    callee_param_name=callee_param_name,
                                    taint_action="REACHES_SINK",
                                    receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                    receiver_confidence=resolved_edge.receiver_confidence if resolved_edge else None,
                                    context_id=ctx_id,
                                )
                                chain = var_call_chains.get(tainted_arg, []) + [step]
                                sink_dict = {
                                    "sink_id": sink_inv.sink_id,
                                    "file_path": getattr(callee_summary, "file_path", fn_def.file_path),
                                    "line": sink_inv.line,
                                    "column": 0,
                                    "expression": f"{callee_name}()",
                                }
                                path = self._build_path(
                                    source_dict=var_sources[tainted_arg],
                                    call_chain=chain,
                                    sink_dict=sink_dict,
                                    category=sink_inv.sink_category,
                                )
                                detected_paths.append(path)

        return detected_paths

    def _analyze_jsts_function(
        self,
        fn_def: FunctionDefinition,
        root_node: Node,
        source_bytes: bytes,
    ) -> list[InterproceduralTaintPath]:
        """Analyze a JS/TS function scope for interprocedural taint flows."""
        analyzer = JSDataFlowAnalyzer(registry=self.registry, is_cancelled=self.is_cancelled)
        fn_nodes = analyzer._find_functions(root_node)
        target_fn_node: Optional[Node] = None

        for fn_node in fn_nodes:
            line_start, _, _, _ = get_node_line_and_col(fn_node)
            if line_start == fn_def.line_start:
                target_fn_node = fn_node
                break

        if not target_fn_node:
            return []

        body_node = target_fn_node.child_by_field_name("body")
        if not body_node:
            for child in target_fn_node.children:
                if child.type in ("statement_block", "expression_statement"):
                    body_node = child
                    break
        if not body_node:
            return []

        # Extract local types
        type_env: Optional[TypeEnvironment] = None
        if not self.disable_type_inference:
            type_env = self.jsts_type_extractor.extract_function_types(
                target_fn_node, source_bytes, fn_def.file_path, enclosing_class=fn_def.class_name
            )
            self.types_inferred_count += len(type_env.bindings)

        detected_paths: list[InterproceduralTaintPath] = []
        var_sources: dict[str, dict[str, Any]] = {}
        var_call_chains: dict[str, list[CallChainStep]] = {}
        var_states: dict[str, TaintState] = {}
        var_sanitizers: dict[str, list[str]] = {}

        statements = [c for c in body_node.children if not c.type.startswith("comment")][:500]

        for stmt in statements:
            self.check_cancellation()

            # 1. Variable declarations: const x = ...
            if stmt.type in ("lexical_declaration", "variable_declaration"):
                for child in stmt.children:
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        val_node = child.child_by_field_name("value")
                        if not name_node or not val_node:
                            continue
                        target_var = node_text(name_node, source_bytes).strip()
                        raw_val = node_text(val_node, source_bytes).strip()
                        line, _, col, _ = get_node_line_and_col(child)

                        source = analyzer._extract_source(val_node, source_bytes)
                        if source:
                            src_dict = {
                                "source_id": source.source_id,
                                "file_path": fn_def.file_path,
                                "line": line,
                                "column": col,
                                "expression": raw_val,
                                "category": source.category.value,
                            }
                            var_sources[target_var] = src_dict
                            var_call_chains[target_var] = []
                            var_states[target_var] = TaintState.TAINTED
                            var_sanitizers[target_var] = []
                            continue

                        # Call expression: const card = buildCard(userInput) or repo.find(userInput)
                        if val_node.type == "call_expression":
                            fn_call_node = val_node.child_by_field_name("function")
                            callee_name = node_text(fn_call_node, source_bytes).strip() if fn_call_node else ""
                            args_node = val_node.child_by_field_name("arguments")
                            if args_node:
                                arg_children = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                                for arg_idx, arg_child in enumerate(arg_children):
                                    arg_names = analyzer._extract_identifier_names(arg_child, source_bytes)
                                    tainted_arg = next((n for n in arg_names if var_states.get(n) == TaintState.TAINTED), None)
                                    if not tainted_arg:
                                        continue

                                    # Type-aware resolution for JS/TS
                                    resolved_edge = None
                                    if isinstance(self.type_resolver, TypeAwareCallResolver):
                                        resolved_edge, _ = self.type_resolver.resolve_call(
                                            caller=fn_def,
                                            callee_expr=callee_name,
                                            line=line,
                                            col=col,
                                            arg_count=len(arg_children),
                                            type_env=type_env,
                                            enclosing_class=fn_def.class_name,
                                        )
                                    target_callee_qn = (
                                        resolved_edge.callee_qualified_name
                                        if resolved_edge and resolved_edge.callee_qualified_name
                                        else callee_name
                                    )

                                    if resolved_edge and resolved_edge.receiver_confidence:
                                        self.type_aware_edges_count += 1
                                        self.confidence_distribution[resolved_edge.receiver_confidence] = (
                                            self.confidence_distribution.get(resolved_edge.receiver_confidence, 0) + 1
                                        )

                                    call_site_id = f"{fn_def.file_path}:{line}:{col}"
                                    if not self.disable_context_sensitivity:
                                        ctx, _ = self.context_manager.get_or_create_context(
                                            callee_qn=target_callee_qn,
                                            parent=CallContext.create_root_context(),
                                            call_site_id=call_site_id,
                                            arg_taints=[
                                                any(var_states.get(n) == TaintState.TAINTED for n in analyzer._extract_identifier_names(a, source_bytes))
                                                for a in arg_children
                                            ],
                                            receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                        )
                                        ctx_id = ctx.context_id
                                    else:
                                        ctx_id = "ROOT"

                                    callee_summary = self.context_summary_manager.get_summary(
                                        target_callee_qn, ctx_id
                                    ) or self._resolve_callee_summary(target_callee_qn, fn_def.file_path)
                                    if not callee_summary:
                                        continue

                                    callee_param_name = (
                                        callee_summary.parameters[arg_idx].name
                                        if hasattr(callee_summary, "parameters") and arg_idx < len(callee_summary.parameters)
                                        else f"arg_{arg_idx}"
                                    )

                                    for sink_inv in callee_summary.sink_invocations:
                                        if sink_inv.receiving_param_index == arg_idx:
                                            step = CallChainStep(
                                                caller_function=fn_def.qualified_name,
                                                callee_function=callee_summary.qualified_name,
                                                caller_file=fn_def.file_path,
                                                callee_file=getattr(callee_summary, "file_path", fn_def.file_path),
                                                call_site_line=line,
                                                call_site_col=col,
                                                argument_index=arg_idx,
                                                callee_param_name=callee_param_name,
                                                taint_action="REACHES_SINK",
                                                receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                                receiver_confidence=resolved_edge.receiver_confidence if resolved_edge else None,
                                                context_id=ctx_id,
                                            )
                                            chain = var_call_chains.get(tainted_arg, []) + [step]
                                            sink_dict = {
                                                "sink_id": sink_inv.sink_id,
                                                "file_path": getattr(callee_summary, "file_path", fn_def.file_path),
                                                "line": sink_inv.line,
                                                "column": 0,
                                                "expression": f"{callee_name}()",
                                            }
                                            path = self._build_path(
                                                source_dict=var_sources[tainted_arg],
                                                call_chain=chain,
                                                sink_dict=sink_dict,
                                                category=sink_inv.sink_category,
                                            )
                                            detected_paths.append(path)

                                    for transfer in callee_summary.taint_transfers:
                                        if transfer.from_param_index == arg_idx and transfer.to_return:
                                            step = CallChainStep(
                                                caller_function=fn_def.qualified_name,
                                                callee_function=callee_summary.qualified_name,
                                                caller_file=fn_def.file_path,
                                                callee_file=getattr(callee_summary, "file_path", fn_def.file_path),
                                                call_site_line=line,
                                                call_site_col=col,
                                                argument_index=arg_idx,
                                                callee_param_name=callee_param_name,
                                                taint_action="PROPAGATE_THROUGH",
                                                receiver_type=resolved_edge.receiver_type if resolved_edge else None,
                                                receiver_confidence=resolved_edge.receiver_confidence if resolved_edge else None,
                                                context_id=ctx_id,
                                            )
                                            if len(var_call_chains.get(tainted_arg, [])) < self.max_call_depth:
                                                var_call_chains[target_var] = var_call_chains.get(tainted_arg, []) + [step]
                                                var_sources[target_var] = var_sources[tainted_arg]
                                                if transfer.sanitized_by:
                                                    var_states[target_var] = TaintState.SANITIZED
                                                    var_sanitizers[target_var] = [transfer.sanitized_by]
                                                else:
                                                    var_states[target_var] = TaintState.TAINTED
                                                    var_sanitizers[target_var] = []
                            continue

                        # Simple propagation
                        names = analyzer._extract_identifier_names(val_node, source_bytes)
                        tainted_name = next((n for n in names if var_states.get(n) == TaintState.TAINTED), None)
                        if tainted_name:
                            var_states[target_var] = TaintState.TAINTED
                            var_sources[target_var] = var_sources[tainted_name]
                            var_call_chains[target_var] = list(var_call_chains.get(tainted_name, []))
                            var_sanitizers[target_var] = list(var_sanitizers.get(tainted_name, []))

            # 2. Expression statement (assignment to innerHTML or call to eval)
            elif stmt.type == "expression_statement":
                for child in stmt.children:
                    if child.type == "assignment_expression":
                        left = child.child_by_field_name("left")
                        right = child.child_by_field_name("right")
                        if not left or not right:
                            continue
                        left_text = node_text(left, source_bytes).strip()
                        right_text = node_text(right, source_bytes).strip()
                        line, _, col, _ = get_node_line_and_col(child)

                        if left.type == "member_expression":
                            prop_node = left.child_by_field_name("property")
                            prop_name = node_text(prop_node, source_bytes).strip() if prop_node else ""
                            if prop_name in ("innerHTML", "outerHTML"):
                                ref_names = analyzer._extract_identifier_names(right, source_bytes)
                                tainted_arg = next((n for n in ref_names if var_states.get(n) == TaintState.TAINTED), None)
                                if tainted_arg:
                                    chain = var_call_chains.get(tainted_arg, [])
                                    if chain and len(chain) >= 1:
                                        sink_dict = {
                                            "sink_id": "DOM_INNERHTML",
                                            "file_path": fn_def.file_path,
                                            "line": line,
                                            "column": col,
                                            "expression": f"{left_text} = {right_text}",
                                        }
                                        path = self._build_path(
                                            source_dict=var_sources[tainted_arg],
                                            call_chain=chain,
                                            sink_dict=sink_dict,
                                            category=SinkCategory.DOM_INJECTION,
                                        )
                                        detected_paths.append(path)

                    elif child.type == "call_expression":
                        fn_node = child.child_by_field_name("function")
                        callee_name = node_text(fn_node, source_bytes).strip() if fn_node else ""
                        line, _, col, _ = get_node_line_and_col(child)
                        args_node = child.child_by_field_name("arguments")
                        if args_node and callee_name in ("eval", "Function", "document.write"):
                            arg_children = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                            for arg in arg_children:
                                ref_names = analyzer._extract_identifier_names(arg, source_bytes)
                                tainted_arg = next((n for n in ref_names if var_states.get(n) == TaintState.TAINTED), None)
                                if tainted_arg:
                                    chain = var_call_chains.get(tainted_arg, [])
                                    if chain and len(chain) >= 1:
                                        cat = SinkCategory.CODE_EVAL if callee_name in ("eval", "Function") else SinkCategory.DOM_INJECTION
                                        sink_dict = {
                                            "sink_id": f"JS_{callee_name.upper()}",
                                            "file_path": fn_def.file_path,
                                            "line": line,
                                            "column": col,
                                            "expression": node_text(child, source_bytes).strip(),
                                        }
                                        path = self._build_path(
                                            source_dict=var_sources[tainted_arg],
                                            call_chain=chain,
                                            sink_dict=sink_dict,
                                            category=cat,
                                        )
                                        detected_paths.append(path)

        return detected_paths

    def _resolve_callee_summary(self, callee_name: str, caller_file: str) -> Optional[FunctionSummary]:
        """Look up function summary by callee name or resolved qualified name."""
        if not callee_name:
            return None
        # Try direct lookup
        if callee_name in self.summaries:
            return self.summaries[callee_name]
        # Try suffix or simple function name match
        for qn, summary in self.summaries.items():
            if qn.endswith(f".{callee_name}") or qn == callee_name:
                return summary
        return None

    def _build_path(
        self,
        source_dict: dict[str, Any],
        call_chain: list[CallChainStep],
        sink_dict: dict[str, Any],
        category: SinkCategory,
    ) -> InterproceduralTaintPath:
        """Construct an InterproceduralTaintPath with deterministic metadata."""
        bounded_chain = call_chain[: self.max_evidence_steps]
        involved_files = set()
        if "file_path" in source_dict:
            involved_files.add(source_dict["file_path"].replace("\\", "/"))
        if "file_path" in sink_dict:
            involved_files.add(sink_dict["file_path"].replace("\\", "/"))
        for step in bounded_chain:
            involved_files.add(step.caller_file.replace("\\", "/"))
            involved_files.add(step.callee_file.replace("\\", "/"))

        # Build readable path summary
        hops = [f"{source_dict.get('source_id', 'SRC')} ({source_dict.get('file_path')}:{source_dict.get('line')})"]
        for step in bounded_chain:
            receiver_info = f" [{step.receiver_type}]" if step.receiver_type else ""
            hops.append(f"{step.callee_function}(){receiver_info} [{step.taint_action}]")
        hops.append(f"{sink_dict.get('sink_id', 'SINK')} ({sink_dict.get('file_path')}:{sink_dict.get('line')})")
        path_summary = " -> ".join(hops)

        return InterproceduralTaintPath(
            flow_type="INTER_PROCEDURAL_TAINT",
            source=source_dict,
            call_chain=bounded_chain,
            sink=sink_dict,
            path_summary=path_summary,
            category=category,
            total_depth=len(bounded_chain),
            files_involved=sorted(list(involved_files)),
        )
