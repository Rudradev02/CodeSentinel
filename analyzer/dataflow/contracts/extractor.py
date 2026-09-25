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
    ExceptionDisposition,
    ExceptionalPostcondition,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    ReturnAliasKind,
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
        exceptional_postconditions: list[ExceptionalPostcondition] = []
        conditional_effects: list[ConditionalTaintEffect] = []

        # 1. Inspect return paths for postconditions
        self._extract_python_postconditions(
            func_node=target_fn,
            paths=paths,
            param_index_map=param_index_map,
            postconditions=postconditions,
            conditional_effects=conditional_effects,
            cfg=cfg,
        )

        # 2. Inspect statements and sinks for preconditions
        self._extract_python_preconditions(
            func_node=target_fn,
            param_index_map=param_index_map,
            preconditions=preconditions,
        )

        # 3. Inspect raise statements for exceptional postconditions and normal-path refinements
        self._extract_python_exceptional_postconditions(
            func_node=target_fn,
            param_index_map=param_index_map,
            exceptional_postconditions=exceptional_postconditions,
            postconditions=postconditions,
        )

        # 4. Inspect return expressions for aliases and container keys
        alias_kind, aliased_p_idx, aliased_field, container_keys = self._extract_python_return_aliases_and_containers(
            func_node=target_fn,
            param_index_map=param_index_map,
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
            qualified_name=target_qn,
            file_path=target_fp,
            context_id=context_id,
            is_pure=self._is_pure_python_function(target_fn),
            preconditions=preconditions,
            postconditions=postconditions,
            exceptional_postconditions=exceptional_postconditions,
            conditional_effects=conditional_effects,
            return_alias_kind=alias_kind,
            return_aliased_param_index=aliased_p_idx,
            return_aliased_field=aliased_field,
            container_key_refinements=container_keys,
            is_widened=explorer.paths_widened > 0,
            extraction_truncated=is_truncated,
        )
        contract.contract_hash = contract.compute_hash()
        return contract

    def _extract_python_exceptional_postconditions(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        param_index_map: dict[str, int],
        exceptional_postconditions: list[ExceptionalPostcondition],
        postconditions: list[SummaryPostcondition],
    ) -> None:
        """Inspect raise statements and validation guards for exceptional postconditions."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.If):
                raises = False
                exc_type = "Exception"
                for stmt in node.body:
                    if isinstance(stmt, ast.Raise):
                        raises = True
                        if stmt.exc is not None:
                            if isinstance(stmt.exc, ast.Call):
                                exc_type = self.guard_evaluator._get_call_name(stmt.exc)
                            elif isinstance(stmt.exc, ast.Name):
                                exc_type = stmt.exc.id
                        break

                if raises:
                    cond_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                    _, raise_facts = self.guard_evaluator.evaluate_python_condition(node.test, expected_value=True)
                    exceptional_postconditions.append(
                        ExceptionalPostcondition(
                            exception_type=exc_type,
                            governing_condition=cond_str,
                            disposition=ExceptionDisposition.MUST_RAISE,
                            parameter_refinements_on_raise=[rf for rf in raise_facts if rf.variable_name in param_index_map],
                        )
                    )
                    # For non-raising fallthrough, negation of condition holds
                    _, normal_facts = self.guard_evaluator.evaluate_python_condition(node.test, expected_value=False)
                    for rf in normal_facts:
                        if rf.variable_name in param_index_map:
                            p_idx = param_index_map[rf.variable_name]
                            if not any(
                                pc.trigger == PostconditionTrigger.UNCONDITIONAL
                                and pc.target_param_index == p_idx
                                and getattr(pc.produced_refinement, "refined_type", None) == rf.refined_type
                                for pc in postconditions
                            ):
                                postconditions.append(
                                    SummaryPostcondition(
                                        trigger=PostconditionTrigger.UNCONDITIONAL,
                                        target_param_index=p_idx,
                                        target_param_name=rf.variable_name,
                                        produced_refinement=rf,
                                        confidence="HIGH",
                                        provenance_line=node.lineno,
                                    )
                                )

    def _extract_python_return_aliases_and_containers(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        param_index_map: dict[str, int],
    ) -> tuple[ReturnAliasKind, Optional[int], Optional[str], dict[str, RefinementFact]]:
        """Inspect return expressions to determine return alias kind and container refinements."""
        alias_kind = ReturnAliasKind.UNKNOWN_ALIAS
        aliased_param_idx = None
        aliased_field = None
        container_keys: dict[str, RefinementFact] = {}

        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                ret_val = node.value
                ret_line = getattr(node, "lineno", 0)

                # Parameter alias: return x
                if isinstance(ret_val, ast.Name) and ret_val.id in param_index_map:
                    alias_kind = ReturnAliasKind.ALIASED_PARAMETER
                    aliased_param_idx = param_index_map[ret_val.id]

                # Field alias: return x.field
                elif isinstance(ret_val, ast.Attribute) and isinstance(ret_val.value, ast.Name):
                    if ret_val.value.id in param_index_map:
                        alias_kind = ReturnAliasKind.ALIASED_FIELD
                        aliased_param_idx = param_index_map[ret_val.value.id]
                        aliased_field = ret_val.attr

                # New allocation: return Dict, List, Set, or Constructor call
                elif isinstance(ret_val, (ast.Dict, ast.List, ast.Set)):
                    alias_kind = ReturnAliasKind.NEW_ALLOCATION
                elif isinstance(ret_val, ast.Call):
                    fn_name = self.guard_evaluator._get_call_name(ret_val)
                    if fn_name and (fn_name[0].isupper() or "." in fn_name and fn_name.split(".")[-1][0].isupper()):
                        alias_kind = ReturnAliasKind.NEW_ALLOCATION

                # Container key extraction from dict literals
                if isinstance(ret_val, ast.Dict):
                    for k, v in zip(ret_val.keys, ret_val.values):
                        if k is not None and isinstance(k, ast.Constant) and isinstance(k.value, str):
                            k_name = k.value
                            if isinstance(v, ast.Call):
                                call_fn = self.guard_evaluator._get_call_name(v)
                                if call_fn in ("int", "float"):
                                    container_keys[k_name] = RefinementFact(
                                        variable_name=k_name,
                                        refined_type=call_fn,
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    )
                                elif call_fn in ("html.escape", "cgi.escape"):
                                    container_keys[k_name] = RefinementFact(
                                        variable_name=k_name,
                                        applicable_sanitizer_category="DOM_INJECTION",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    )
                                elif call_fn == "shlex.quote":
                                    container_keys[k_name] = RefinementFact(
                                        variable_name=k_name,
                                        applicable_sanitizer_category="COMMAND_EXECUTE",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    )
                            elif isinstance(v, ast.Constant):
                                if isinstance(v.value, int):
                                    container_keys[k_name] = RefinementFact(
                                        variable_name=k_name,
                                        refined_type="int",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    )
                                elif isinstance(v.value, str):
                                    container_keys[k_name] = RefinementFact(
                                        variable_name=k_name,
                                        refined_type="str",
                                        is_non_null=True,
                                        provenance_line=ret_line,
                                    )
                            elif isinstance(v, ast.Name) and v.id in param_index_map:
                                container_keys[k_name] = RefinementFact(
                                    variable_name=k_name,
                                    is_non_null=True,
                                    provenance_line=ret_line,
                                )

        return alias_kind, aliased_param_idx, aliased_field, container_keys

    def _extract_python_postconditions(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        paths: list[Any],
        param_index_map: dict[str, int],
        postconditions: list[SummaryPostcondition],
        conditional_effects: list[ConditionalTaintEffect],
        cfg: Optional[ControlFlowGraph] = None,
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

        # Case 3: Branch-Correlated Returns from AST and CFG Paths
        # e.g.:
        # if isinstance(x, int):
        #     return True
        # return False
        for node in ast.walk(func_node):
            if isinstance(node, ast.If):
                ret_true = False
                ret_false = False
                ret_line = node.lineno
                for stmt in node.body:
                    if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                        if stmt.value.value is True:
                            ret_true = True
                        elif stmt.value.value is False:
                            ret_false = True
                        ret_line = stmt.lineno
                if ret_true or ret_false:
                    expected_val = True if ret_true else False
                    _, facts = self.guard_evaluator.evaluate_python_condition(node.test, expected_val)
                    trigger = PostconditionTrigger.RETURN_EQUALS_TRUE if ret_true else PostconditionTrigger.RETURN_EQUALS_FALSE
                    for rf in facts:
                        if rf.variable_name in param_index_map:
                            p_idx = param_index_map[rf.variable_name]
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
                                        target_param_name=rf.variable_name,
                                        produced_refinement=rf,
                                        confidence="HIGH",
                                        provenance_line=ret_line,
                                    )
                                )

        # Case 3b: Conditional Sanitizers across branches
        for node in ast.walk(func_node):
            if isinstance(node, ast.If):
                test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                matching_param = next((p for p in param_index_map if p in test_str), None)
                if matching_param:
                    for stmt in node.body:
                        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                            fn_name = self.guard_evaluator._get_call_name(stmt.value)
                            if fn_name == "shlex.quote" and stmt.value.args:
                                arg_var = self.guard_evaluator._extract_var_name(stmt.value.args[0])
                                if arg_var in param_index_map:
                                    conditional_effects.append(
                                        ConditionalTaintEffect(
                                            from_param_index=param_index_map[arg_var],
                                            to_return=True,
                                            governing_path_condition=f"{matching_param} == True",
                                            effect_kind=EffectKind.APPLIES_SANITIZER,
                                            sanitizer_applied="shlex.quote",
                                            sanitizer_category=SinkCategory.COMMAND_EXECUTE,
                                        )
                                    )
            elif isinstance(node, ast.Return) and isinstance(node.value, ast.IfExp):
                test_str = ast.unparse(node.value.test) if hasattr(ast, "unparse") else ""
                matching_param = next((p for p in param_index_map if p in test_str), None)
                if matching_param:
                    if isinstance(node.value.body, ast.Call):
                        fn_name = self.guard_evaluator._get_call_name(node.value.body)
                        if fn_name == "shlex.quote" and node.value.body.args:
                            arg_var = self.guard_evaluator._extract_var_name(node.value.body.args[0])
                            if arg_var in param_index_map:
                                conditional_effects.append(
                                    ConditionalTaintEffect(
                                        from_param_index=param_index_map[arg_var],
                                        to_return=True,
                                        governing_path_condition=f"{matching_param} == True",
                                        effect_kind=EffectKind.APPLIES_SANITIZER,
                                        sanitizer_applied="shlex.quote",
                                        sanitizer_category=SinkCategory.COMMAND_EXECUTE,
                                    )
                                )

        # Case 3c: Branch-Correlated Returns across CFG Paths
        for p in paths:
            constraints = p.constraints
            if not constraints or constraints.feasibility.value != "FEASIBLE":
                continue

            for var_name, r_facts in constraints.refinement_facts.items():
                if var_name not in param_index_map:
                    continue
                p_idx = param_index_map[var_name]

                block = cfg.blocks.get(p.current_block_id) if hasattr(p, "current_block_id") and cfg else None
                block_stmts = block.statements if block else []
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
        func_node: Optional[Node] = None,
        file_path: Optional[str] = None,
        qualified_name: Optional[str] = None,
        source_code: Optional[str] = None,
        context_id: str = "ROOT",
        fn_def: Optional[Any] = None,
        fn_node: Optional[Node] = None,
        source_bytes: Optional[bytes] = None,
        const_args: Optional[dict[int, Any]] = None,
    ) -> FunctionContract:
        """Extract a FunctionContract for a JavaScript / TypeScript function."""
        if self.is_cancelled and self.is_cancelled():
            from analyzer.models.errors import AnalysisCancelledError
            raise AnalysisCancelledError("Contract extraction cancelled")

        target_node = func_node or fn_node
        if fn_def:
            file_path = file_path or fn_def.file_path
            qualified_name = qualified_name or fn_def.qualified_name

        if source_code is None and source_bytes is not None:
            source_code = source_bytes.decode("utf-8", errors="replace")
        elif source_code is None:
            source_code = ""

        if target_node is None:
            contract = FunctionContract(
                qualified_name=qualified_name or "unknown",
                file_path=file_path or "unknown",
                context_id=context_id,
            )
            contract.contract_hash = contract.compute_hash()
            return contract

        # Parse parameter names from parameter list
        param_names: list[str] = []
        params_node = target_node.child_by_field_name("parameters")
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
            func_node=target_node,
            param_index_map=param_index_map,
            postconditions=postconditions,
            source_code=source_code,
        )

        contract = FunctionContract(
            qualified_name=qualified_name or "unknown",
            file_path=file_path or "unknown",
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
