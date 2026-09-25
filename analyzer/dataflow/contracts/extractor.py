"""Intraprocedural contract extraction engine for Python and JS/TS (Phase 19).

Extracts formal FunctionContracts from CFG basic blocks, feasible execution paths,
return statements, and internal sink reachability.
"""

import ast
from typing import Any, Callable, Optional
from tree_sitter import Node

from analyzer.dataflow.cfg.guard_evaluator import GuardEvaluator
from analyzer.dataflow.cfg.jsts_cfg_builder import JSTSCFGBuilder
from analyzer.dataflow.cfg.models import BasicBlock, ControlFlowGraph, GuardCondition, PredicateOp, RefinementFact
from analyzer.dataflow.cfg.path_explorer import PathExplorer
from analyzer.dataflow.cfg.python_cfg_builder import PythonCFGBuilder
from analyzer.dataflow.contracts.models import (
    ConditionalTaintEffect,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.taint.models import SinkCategory, TaintState


class ContractExtractor:
    """Synthesizes deterministic FunctionContracts from AST bodies and CFG exploration."""

    def __init__(
        self,
        guard_evaluator: Optional[GuardEvaluator] = None,
        max_preconditions: int = 8,
        max_postconditions: int = 16,
        max_effects: int = 16,
        max_field_depth: int = 3,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.guard_evaluator = guard_evaluator or GuardEvaluator()
        self.max_preconditions = max_preconditions
        self.max_postconditions = max_postconditions
        self.max_effects = max_effects
        self.max_field_depth = max_field_depth
        self.is_cancelled = is_cancelled
        self.python_cfg_builder = PythonCFGBuilder(is_cancelled=is_cancelled)
        self.jsts_cfg_builder = JSTSCFGBuilder()

    def extract_python_contract(
        self,
        func_node: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None,
        file_path: Optional[str] = None,
        qualified_name: Optional[str] = None,
        context_id: str = "ROOT",
        fn_def: Optional[Any] = None,
        fn_node: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None,
        const_args: Optional[dict[int, Any]] = None,
    ) -> FunctionContract:
        """Extract a FunctionContract for a Python function."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Contract extraction cancelled")

        target_fn = func_node or fn_node
        if target_fn is None:
            raise ValueError("func_node or fn_node must be provided")
        target_fp = file_path or (fn_def.file_path if fn_def else "")
        target_qn = qualified_name or (fn_def.qualified_name if fn_def else (target_fn.name if hasattr(target_fn, "name") else ""))

        param_names = [arg.arg for arg in target_fn.args.args if arg.arg not in ("self", "cls")]
        param_index_map = {name: idx for idx, name in enumerate(param_names)}

        # Build CFG and explore paths
        cfg = self.python_cfg_builder.build_cfg(
            target_fn, file_path=target_fp, function_qualified_name=target_qn
        )
        explorer = PathExplorer(
            max_active_paths=8,
            max_total_path_states=64,
            max_branch_depth=6,
            is_cancelled=self.is_cancelled,
        )
        paths = explorer.explore_paths(cfg)

        preconditions: list[SummaryPrecondition] = []
        postconditions: list[SummaryPostcondition] = []
        conditional_effects: list[ConditionalTaintEffect] = []

        # 1. Inspect return paths for postconditions
        self._extract_python_postconditions(
            func_node=func_node,
            paths=paths,
            param_index_map=param_index_map,
            postconditions=postconditions,
            conditional_effects=conditional_effects,
        )

        # 2. Inspect statements and sinks for preconditions
        self._extract_python_preconditions(
            func_node=func_node,
            param_index_map=param_index_map,
            preconditions=preconditions,
        )

        # Truncate to bounds
        is_truncated = (
            len(preconditions) > self.max_preconditions
            or len(postconditions) > self.max_postconditions
            or len(conditional_effects) > self.max_effects
        )
        preconditions = preconditions[:self.max_preconditions]
        postconditions = postconditions[:self.max_postconditions]
        conditional_effects = conditional_effects[:self.max_effects]

        contract = FunctionContract(
            qualified_name=qualified_name,
            file_path=file_path,
            context_id=context_id,
            is_pure=self._is_pure_python_function(func_node),
            preconditions=preconditions,
            postconditions=postconditions,
            conditional_effects=conditional_effects,
            is_widened=explorer.paths_widened > 0,
            extraction_truncated=is_truncated,
        )
        contract.contract_hash = contract.compute_hash()
        return contract

    def _extract_python_postconditions(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        paths: list[Any],
        param_index_map: dict[str, int],
        postconditions: list[SummaryPostcondition],
        conditional_effects: list[ConditionalTaintEffect],
    ) -> None:
        """Inspect return statements across CFG paths to extract proven postconditions."""
        # Find all return statements
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                ret_val = node.value
                ret_line = getattr(node, "lineno", 0)

                # Case 1: Direct boolean predicate return, e.g. return isinstance(x, int)
                # or return x.isdigit() or return re.match(r'^[a-z]+$', x)
                conds, facts = self.guard_evaluator.evaluate_python_condition(ret_val, expected_value=True)
                if conds and facts:
                    for fact in facts:
                        if fact.variable_name in param_index_map:
                            p_idx = param_index_map[fact.variable_name]
                            postconditions.append(
                                SummaryPostcondition(
                                    trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                                    target_param_index=p_idx,
                                    target_param_name=fact.variable_name,
                                    produced_refinement=fact,
                                    confidence="HIGH",
                                    provenance_line=ret_line,
                                )
                            )

                # Case 2: Normalization / Sanitizer calls on return: return shlex.quote(x), return int(x), etc.
                if isinstance(ret_val, ast.Call):
                    fn_name = self.guard_evaluator._get_call_name(ret_val)
                    if fn_name == "shlex.quote" and ret_val.args:
                        arg_var = self.guard_evaluator._extract_var_name(ret_val.args[0])
                        if arg_var in param_index_map:
                            postconditions.append(
                                SummaryPostcondition(
                                    trigger=PostconditionTrigger.UNCONDITIONAL,
                                    target_param_index=param_index_map[arg_var],
                                    target_param_name=arg_var,
                                    applies_to_return=True,
                                    applicable_sanitizer_category=SinkCategory.COMMAND_EXECUTE,
                                    produced_refinement=RefinementFact(
                                        variable_name="return",
                                        applicable_sanitizer_category="COMMAND_EXECUTE",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    ),
                                    confidence="HIGH",
                                    provenance_line=ret_line,
                                )
                            )
                    elif fn_name in ("int", "float") and ret_val.args:
                        arg_var = self.guard_evaluator._extract_var_name(ret_val.args[0])
                        if arg_var in param_index_map:
                            postconditions.append(
                                SummaryPostcondition(
                                    trigger=PostconditionTrigger.UNCONDITIONAL,
                                    target_param_index=param_index_map[arg_var],
                                    target_param_name=arg_var,
                                    applies_to_return=True,
                                    produced_refinement=RefinementFact(
                                        variable_name="return",
                                        refined_type=fn_name,
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    ),
                                    confidence="HIGH",
                                    provenance_line=ret_line,
                                )
                            )
                    elif fn_name in ("html.escape", "cgi.escape") and ret_val.args:
                        arg_var = self.guard_evaluator._extract_var_name(ret_val.args[0])
                        if arg_var in param_index_map:
                            postconditions.append(
                                SummaryPostcondition(
                                    trigger=PostconditionTrigger.UNCONDITIONAL,
                                    target_param_index=param_index_map[arg_var],
                                    target_param_name=arg_var,
                                    applies_to_return=True,
                                    applicable_sanitizer_category=SinkCategory.DOM_INJECTION,
                                    produced_refinement=RefinementFact(
                                        variable_name="return",
                                        applicable_sanitizer_category="DOM_INJECTION",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    ),
                                    confidence="HIGH",
                                    provenance_line=ret_line,
                                )
                            )

        # Case 3: Branch-Correlated Returns across CFG Paths
        # e.g.:
        # if isinstance(x, int):
        #     return True
        # return False
        for p in paths:
            constraints = p.constraints
            if not constraints or constraints.feasibility.value != "FEASIBLE":
                continue

            # Look for refined facts on parameters
            for var_name, r_facts in constraints.refinement_facts.items():
                if var_name not in param_index_map:
                    continue
                p_idx = param_index_map[var_name]

                # Check if this path's terminating block returns literal True or False
                block_stmts = getattr(p, "terminating_statements", [])
                for stmt in block_stmts:
                    if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                        ret_val = stmt.value.value
                        ret_line = getattr(stmt, "lineno", 0)
                        if isinstance(ret_val, bool):
                            trigger = (
                                PostconditionTrigger.RETURN_EQUALS_TRUE
                                if ret_val is True
                                else PostconditionTrigger.RETURN_EQUALS_FALSE
                            )
                            for rf in r_facts:
                                # Avoid duplicating identical postconditions
                                if not any(
                                    pc.trigger == trigger
                                    and pc.target_param_index == p_idx
                                    and getattr(pc.produced_refinement, "refined_type", None) == rf.refined_type
                                    and getattr(pc.produced_refinement, "is_numeric_string", False) == rf.is_numeric_string
                                    for pc in postconditions
                                ):
                                    postconditions.append(
                                        SummaryPostcondition(
                                            trigger=trigger,
                                            target_param_index=p_idx,
                                            target_param_name=var_name,
                                            produced_refinement=rf,
                                            confidence="HIGH",
                                            provenance_line=ret_line,
                                        )
                                    )

        # Case 4: Field mutations, e.g. obj.token = clean(obj.token)
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        base_var = target.value.id
                        field_name = target.attr
                        if base_var in param_index_map:
                            p_idx = param_index_map[base_var]
                            # Check if RHS has a sanitizer
                            if isinstance(node.value, ast.Call):
                                fn_name = self.guard_evaluator._get_call_name(node.value)
                                if fn_name == "shlex.quote":
                                    postconditions.append(
                                        SummaryPostcondition(
                                            trigger=PostconditionTrigger.UNCONDITIONAL,
                                            target_param_index=p_idx,
                                            target_param_name=base_var,
                                            target_field_name=field_name,
                                            applicable_sanitizer_category=SinkCategory.COMMAND_EXECUTE,
                                            produced_refinement=RefinementFact(
                                                variable_name=f"{base_var}.{field_name}",
                                                applicable_sanitizer_category="COMMAND_EXECUTE",
                                                is_non_null=True,
                                                provenance_line=node.lineno,
                                            ),
                                            confidence="HIGH",
                                            provenance_line=node.lineno,
                                        )
                                    )
                                elif fn_name in ("int", "float"):
                                    postconditions.append(
                                        SummaryPostcondition(
                                            trigger=PostconditionTrigger.UNCONDITIONAL,
                                            target_param_index=p_idx,
                                            target_param_name=base_var,
                                            target_field_name=field_name,
                                            produced_refinement=RefinementFact(
                                                variable_name=f"{base_var}.{field_name}",
                                                refined_type=fn_name,
                                                is_non_null=True,
                                                provenance_line=node.lineno,
                                            ),
                                            confidence="HIGH",
                                            provenance_line=node.lineno,
                                        )
                                    )

    def _extract_python_preconditions(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        param_index_map: dict[str, int],
        preconditions: list[SummaryPrecondition],
    ) -> None:
        """Inspect sink invocations within the function body to infer caller preconditions."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                fn_name = self.guard_evaluator._get_call_name(node)
                line = getattr(node, "lineno", 0)

                # Check SQL execute sinks
                if fn_name.endswith(".execute") or fn_name in ("execute", "cursor.execute", "conn.execute"):
                    if node.args:
                        arg_names = self.guard_evaluator._extract_names(node.args[0])
                        for p_name in arg_names:
                            if p_name in param_index_map:
                                p_idx = param_index_map[p_name]
                                preconditions.append(
                                    SummaryPrecondition(
                                        target_param_index=p_idx,
                                        target_param_name=p_name,
                                        kind=PreconditionKind.TYPE_REFINEMENT,
                                        required_type="int",
                                        sink_category=SinkCategory.SQL_EXECUTE,
                                        raw_condition=f"isinstance({p_name}, (int, float)) or {p_name}.isdigit()",
                                        line=line,
                                        provenance_sink_id="SQL_EXECUTE",
                                    )
                                )

                # Check OS command sinks
                elif fn_name in ("os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen"):
                    if node.args:
                        arg_names = self.guard_evaluator._extract_names(node.args[0])
                        for p_name in arg_names:
                            if p_name in param_index_map:
                                p_idx = param_index_map[p_name]
                                preconditions.append(
                                    SummaryPrecondition(
                                        target_param_index=p_idx,
                                        target_param_name=p_name,
                                        kind=PreconditionKind.FORMAT_REFINEMENT,
                                        required_type="is_alphanumeric_string",
                                        sink_category=SinkCategory.COMMAND_EXECUTE,
                                        raw_condition=f"{p_name}.isalnum() or shlex.quote({p_name})",
                                        line=line,
                                        provenance_sink_id="COMMAND_EXECUTE",
                                    )
                                )

    def extract_jsts_contract(
        self,
        func_node: Node,
        file_path: str,
        qualified_name: str,
        source_code: str,
        context_id: str = "ROOT",
    ) -> FunctionContract:
        """Extract a FunctionContract for a JavaScript / TypeScript function."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.exceptions import AnalysisCancelledError
            raise AnalysisCancelledError("Contract extraction cancelled")

        # Parse parameter names from parameter list
        param_names: list[str] = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    param_names.append(child.text.decode("utf-8"))
                elif child.type == "required_parameter":
                    pattern_child = child.child_by_field_name("pattern")
                    if pattern_child:
                        param_names.append(pattern_child.text.decode("utf-8"))

        param_index_map = {name: idx for idx, name in enumerate(param_names)}
        preconditions: list[SummaryPrecondition] = []
        postconditions: list[SummaryPostcondition] = []
        conditional_effects: list[ConditionalTaintEffect] = []

        # Walk JS/TS AST for returns
        self._extract_jsts_returns(
            func_node=func_node,
            param_index_map=param_index_map,
            postconditions=postconditions,
            source_code=source_code,
        )

        contract = FunctionContract(
            qualified_name=qualified_name,
            file_path=file_path,
            context_id=context_id,
            is_pure=False,
            preconditions=preconditions,
            postconditions=postconditions,
            conditional_effects=conditional_effects,
            is_widened=False,
            extraction_truncated=False,
        )
        contract.contract_hash = contract.compute_hash()
        return contract

    def _extract_jsts_returns(
        self,
        func_node: Node,
        param_index_map: dict[str, int],
        postconditions: list[SummaryPostcondition],
        source_code: str,
    ) -> None:
        """Inspect JS/TS return statements to synthesize postconditions."""
        # Simple recursive search for return_statement nodes
        def _walk(node: Node):
            if node.type == "return_statement":
                # Look at expression returned
                for child in node.children:
                    if child.type not in ("return", ";"):
                        expr_str = child.text.decode("utf-8").strip()
                        conds, facts = self.guard_evaluator.evaluate_jsts_condition(expr_str, expected_value=True)
                        for fact in facts:
                            if fact.variable_name in param_index_map:
                                p_idx = param_index_map[fact.variable_name]
                                postconditions.append(
                                    SummaryPostcondition(
                                        trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                                        target_param_index=p_idx,
                                        target_param_name=fact.variable_name,
                                        produced_refinement=fact,
                                        confidence="HIGH",
                                        provenance_line=node.start_point[0] + 1,
                                    )
                                )
            for child in node.children:
                # Do not recurse into nested function bodies
                if child.type not in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
                    _walk(child)

        _walk(func_node)

    def _is_pure_python_function(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if a Python function has no obvious side effects (no global/nonlocal mutations, no IO)."""
        for node in ast.walk(func_node):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                return False
            if isinstance(node, ast.Call):
                fn = self.guard_evaluator._get_call_name(node)
                if fn in ("print", "open", "os.system", "subprocess.call"):
                    return False
        return True
