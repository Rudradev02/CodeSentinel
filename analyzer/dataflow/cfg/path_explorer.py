"""Bounded path explorer and feasibility engine (Phase 18).

Explores intraprocedural CFG execution paths with propositional contradiction checking,
early-exit pruning, branch-state environment joins (taint, alias, field, refinements),
and deterministic widening upon budget exhaustion.
"""

from typing import Any, Callable, Optional

from analyzer.dataflow.cfg.guard_evaluator import GuardEvaluator
from analyzer.dataflow.cfg.models import (
    BasicBlock,
    BranchKind,
    CFGEdge,
    ControlFlowGraph,
    GuardCondition,
    PathConstraint,
    PathFeasibilityStatus,
    PathState,
    PredicateOp,
    RefinementFact,
)
from analyzer.models.errors import AnalysisCancelledError


class PathExplorer:
    """Explores feasible execution paths through a ControlFlowGraph under strict resource bounds."""

    def __init__(
        self,
        guard_evaluator: Optional[GuardEvaluator] = None,
        max_active_paths: int = 8,
        max_total_path_states: int = 128,
        max_branch_depth: int = 6,
        max_loop_iterations: int = 2,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ):
        self.guard_evaluator = guard_evaluator or GuardEvaluator()
        self.max_active_paths = max_active_paths
        self.max_total_path_states = max_total_path_states
        self.max_branch_depth = max_branch_depth
        self.max_loop_iterations = max_loop_iterations
        self.is_cancelled = is_cancelled

        # Diagnostics & counters
        self.total_paths_explored = 0
        self.infeasible_paths_pruned = 0
        self.paths_widened = 0
        self.depth_truncated = 0
        self.guards_evaluated = 0

    def check_cancellation(self) -> None:
        if self.is_cancelled and self.is_cancelled():
            raise AnalysisCancelledError("Path exploration was cancelled by user")

    def explore_paths(
        self,
        cfg: ControlFlowGraph,
        initial_var_states: Optional[dict[str, str]] = None,
        initial_alias_bindings: Optional[dict[str, list[str]]] = None,
        initial_field_states: Optional[dict[str, str]] = None,
    ) -> list[PathState]:
        """Explore all feasible bounded paths through the CFG, returning terminal PathStates."""
        self.check_cancellation()
        self.total_paths_explored = 0
        self.infeasible_paths_pruned = 0
        self.paths_widened = 0
        self.depth_truncated = 0
        self.guards_evaluated = 0

        root_state = PathState(
            path_id="p_0",
            current_block_id=cfg.entry_block_id,
            var_states=dict(initial_var_states or {}),
            alias_bindings=dict(initial_alias_bindings or {}),
            field_states=dict(initial_field_states or {}),
        )

        active_paths: list[PathState] = [root_state]
        completed_paths: list[PathState] = []
        loop_iterations: dict[str, int] = {}  # loop_header_id -> iteration count
        block_visit_states: dict[str, list[PathState]] = {} # block_id -> states arriving at block

        state_counter = 0

        while active_paths:
            self.check_cancellation()
            state_counter += 1
            if state_counter > self.max_total_path_states:
                # Total state budget reached: widen remaining active paths
                self.paths_widened += len(active_paths)
                for p in active_paths:
                    p.constraints.is_widened = True
                    p.constraints.feasibility = PathFeasibilityStatus.WIDENED
                    completed_paths.append(p)
                break

            curr_path = active_paths.pop(0)

            # If current block is exit or early exit, path is complete
            curr_block = cfg.blocks.get(curr_path.current_block_id)
            if not curr_block or curr_block.is_exit or curr_path.current_block_id == cfg.exit_block_id or curr_path.is_terminated:
                curr_path.is_terminated = True
                completed_paths.append(curr_path)
                self.total_paths_explored += 1
                continue

            successors = cfg.get_successors(curr_path.current_block_id)
            if not successors:
                curr_path.is_terminated = True
                completed_paths.append(curr_path)
                self.total_paths_explored += 1
                continue

            # Branch depth check
            if curr_path.branch_depth >= self.max_branch_depth:
                self.depth_truncated += 1
                curr_path.constraints.is_truncated = True
                curr_path.constraints.feasibility = PathFeasibilityStatus.TRUNCATED
                # Route unconditionally to exit
                curr_path.current_block_id = cfg.exit_block_id
                active_paths.append(curr_path)
                continue

            # Check for path budget exhaustion at current block
            if len(active_paths) >= self.max_active_paths and len(successors) > 1:
                # Widen: merge successor paths rather than forking
                self.paths_widened += 1
                merged_target_id = successors[0][0].id
                curr_path.constraints.is_widened = True
                curr_path.constraints.feasibility = PathFeasibilityStatus.WIDENED
                curr_path.current_block_id = merged_target_id
                active_paths.append(curr_path)
                continue

            # Process edges
            for next_block, edge in successors:
                # 1. Early-exit edge (return/raise/throw)
                if edge.kind == BranchKind.EARLY_EXIT:
                    new_path = self._clone_path(curr_path, f"{curr_path.path_id}_exit")
                    new_path.current_block_id = next_block.id
                    new_path.is_terminated = True
                    completed_paths.append(new_path)
                    self.total_paths_explored += 1
                    continue

                # 2. Loop back-edge: enforce loop iteration budget
                if edge.kind == BranchKind.LOOP_BACK:
                    loop_header_id = next_block.id
                    iters = loop_iterations.get(loop_header_id, 0) + 1
                    loop_iterations[loop_header_id] = iters
                    if iters >= self.max_loop_iterations:
                        # Exceeded loop iterations: find LOOP_EXIT edge and follow it
                        loop_exit_edges = [e for e in cfg.edges if e.source_block_id == loop_header_id and e.kind == BranchKind.LOOP_EXIT]
                        if loop_exit_edges:
                            exit_target = loop_exit_edges[0].target_block_id
                            exit_p = self._clone_path(curr_path, f"{curr_path.path_id}_loopexit")
                            exit_p.current_block_id = exit_target
                            exit_p.constraints.is_widened = True
                            active_paths.append(exit_p)
                        continue

                # 3. Branch with condition (TRUE_BRANCH, FALSE_BRANCH)
                if edge.kind in (BranchKind.TRUE_BRANCH, BranchKind.FALSE_BRANCH):
                    is_true_branch = (edge.kind == BranchKind.TRUE_BRANCH)
                    branch_tag = "T" if is_true_branch else "F"
                    new_path = self._clone_path(curr_path, f"{curr_path.path_id}_{branch_tag}_{next_block.id}")
                    new_path.branch_depth += 1

                    # Evaluate condition
                    if edge.condition_ast is not None:
                        self.guards_evaluated += 1
                        conds, facts = self.guard_evaluator.evaluate_python_condition(
                            edge.condition_ast,
                            expected_value=is_true_branch,
                        )
                        for c in conds:
                            new_path.constraints.add_condition(c)
                        for f in facts:
                            new_path.constraints.add_refinement(f)

                    elif edge.condition_expr:
                        self.guards_evaluated += 1
                        conds, facts = self.guard_evaluator.evaluate_jsts_condition(
                            edge.condition_expr,
                            expected_value=is_true_branch,
                        )
                        for c in conds:
                            new_path.constraints.add_condition(c)
                        for f in facts:
                            new_path.constraints.add_refinement(f)

                    # Check feasibility
                    if self.is_path_infeasible(new_path.constraints):
                        self.infeasible_paths_pruned += 1
                        new_path.constraints.feasibility = PathFeasibilityStatus.INFEASIBLE
                        continue

                    new_path.current_block_id = next_block.id
                    active_paths.append(new_path)

                # 4. Unconditional edge
                else:
                    new_path = self._clone_path(curr_path, f"{curr_path.path_id}_{next_block.id}")
                    new_path.current_block_id = next_block.id
                    active_paths.append(new_path)

        return completed_paths

    def is_path_infeasible(self, constraints: PathConstraint) -> bool:
        """Check for propositional contradictions in path conditions."""
        conds = constraints.conditions
        if not conds:
            return False

        # 1. Contradictory polarities of same variable and predicate
        seen: dict[tuple[str, PredicateOp, Optional[str]], bool] = {}
        for c in conds:
            key = (c.variable_name, c.predicate_op, c.argument_literal)
            if key in seen:
                if seen[key] != c.expected_value:
                    constraints.contradiction_reason = f"Opposite branch values for {c.raw_expression}"
                    return True
            else:
                seen[key] = c.expected_value

        # 2. None vs Not None contradiction
        none_vars: set[str] = set()
        not_none_vars: set[str] = set()
        for c in conds:
            if c.predicate_op == PredicateOp.IS_NONE and c.expected_value is True:
                none_vars.add(c.variable_name)
            elif c.predicate_op == PredicateOp.IS_NOT_NONE and c.expected_value is True:
                not_none_vars.add(c.variable_name)
        if none_vars.intersection(not_none_vars):
            constraints.contradiction_reason = "Contradiction: variable is None and is not None"
            return True

        # 3. Disjoint type narrowing: isinstance(x, int) and isinstance(x, str)
        type_vars: dict[str, str] = {}
        for c in conds:
            if c.predicate_op == PredicateOp.IS_INSTANCE and c.expected_value is True and c.argument_literal:
                t = c.argument_literal.lower()
                if c.variable_name in type_vars:
                    prev_t = type_vars[c.variable_name]
                    if prev_t != t and not (("int" in prev_t and "float" in t) or ("float" in prev_t and "int" in t)):
                        constraints.contradiction_reason = f"Contradiction: disjoint types {prev_t} vs {t}"
                        return True
                else:
                    type_vars[c.variable_name] = t

        return False

    def join_states(self, state_a: PathState, state_b: PathState, target_block_id: str) -> PathState:
        """Formal lattice join of two PathStates at a CFG join node."""
        # 1. Taint state join: TAINTED | any = TAINTED
        all_vars = set(state_a.var_states.keys()).union(set(state_b.var_states.keys()))
        merged_taint: dict[str, str] = {}
        for v in all_vars:
            t_a = state_a.var_states.get(v, "UNTAINTED")
            t_b = state_b.var_states.get(v, "UNTAINTED")
            if t_a == "TAINTED" or t_b == "TAINTED":
                merged_taint[v] = "TAINTED"
            elif t_a == "SANITIZED" and t_b == "SANITIZED":
                merged_taint[v] = "SANITIZED"
            else:
                merged_taint[v] = "UNTAINTED"

        # 2. Points-to set join: union of candidate IDs
        all_aliases = set(state_a.alias_bindings.keys()).union(set(state_b.alias_bindings.keys()))
        merged_aliases: dict[str, list[str]] = {}
        for a in all_aliases:
            c_a = state_a.alias_bindings.get(a, [])
            c_b = state_b.alias_bindings.get(a, [])
            merged_aliases[a] = sorted(list(set(c_a).union(set(c_b))))[:4]

        # 3. Field state join: union per field key
        all_fields = set(state_a.field_states.keys()).union(set(state_b.field_states.keys()))
        merged_fields: dict[str, str] = {}
        for f in all_fields:
            ft_a = state_a.field_states.get(f, "UNTAINTED")
            ft_b = state_b.field_states.get(f, "UNTAINTED")
            if ft_a == "TAINTED" or ft_b == "TAINTED":
                merged_fields[f] = "TAINTED"
            elif ft_a == "SANITIZED" and ft_b == "SANITIZED":
                merged_fields[f] = "SANITIZED"
            else:
                merged_fields[f] = "UNTAINTED"

        # 4. Refinement facts: monotonic intersection (only facts proven on all paths survive!)
        merged_refinements: dict[str, list[RefinementFact]] = {}
        for var_name, facts_a in state_a.constraints.refinement_facts.items():
            if var_name in state_b.constraints.refinement_facts:
                facts_b = state_b.constraints.refinement_facts[var_name]
                # Keep facts matching in type or numeric properties
                common = []
                for fa in facts_a:
                    for fb in facts_b:
                        if fa.refined_type and fa.refined_type == fb.refined_type:
                            common.append(fa)
                        elif fa.is_numeric_string and fb.is_numeric_string:
                            common.append(fa)
                if common:
                    merged_refinements[var_name] = common

        merged_constraints = PathConstraint(
            conditions=state_a.constraints.conditions + state_b.constraints.conditions,
            refinement_facts=merged_refinements,
            is_widened=True,
            feasibility=PathFeasibilityStatus.WIDENED,
        )

        return PathState(
            path_id=f"{state_a.path_id}_join_{state_b.path_id}",
            current_block_id=target_block_id,
            constraints=merged_constraints,
            var_states=merged_taint,
            alias_bindings=merged_aliases,
            field_states=merged_fields,
            branch_depth=max(state_a.branch_depth, state_b.branch_depth),
        )

    def _clone_path(self, path: PathState, new_id: str) -> PathState:
        """Deep clone of a path state."""
        return PathState(
            path_id=new_id,
            current_block_id=path.current_block_id,
            constraints=PathConstraint(
                conditions=list(path.constraints.conditions),
                refinement_facts={k: list(v) for k, v in path.constraints.refinement_facts.items()},
                feasibility=path.constraints.feasibility,
                is_widened=path.constraints.is_widened,
                is_truncated=path.constraints.is_truncated,
            ),
            var_states=dict(path.var_states),
            alias_bindings={k: list(v) for k, v in path.alias_bindings.items()},
            field_states=dict(path.field_states),
            call_chain=list(path.call_chain),
            branch_depth=path.branch_depth,
            is_terminated=path.is_terminated,
        )
