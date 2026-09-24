"""Unit tests for Phase 18 CFG and Path Sensitivity Domain Models."""

import pytest
from analyzer.dataflow.cfg.models import (
    BasicBlock,
    BranchKind,
    CFGEdge,
    CompositeCondition,
    ControlFlowGraph,
    GuardCondition,
    PathConstraint,
    PathFeasibilityStatus,
    PathState,
    PredicateOp,
    RefinementFact,
)


def test_basic_block_and_cfg_creation():
    b_entry = BasicBlock(
        id="bb_0",
        function_qualified_name="app.views.login",
        file_path="app/views.py",
        start_line=1,
        end_line=3,
        is_entry=True,
    )
    b_exit = BasicBlock(
        id="bb_exit",
        function_qualified_name="app.views.login",
        file_path="app/views.py",
        start_line=10,
        end_line=10,
        is_exit=True,
    )
    edge = CFGEdge(
        source_block_id="bb_0",
        target_block_id="bb_exit",
        kind=BranchKind.UNCONDITIONAL,
    )

    cfg = ControlFlowGraph(
        function_qualified_name="app.views.login",
        file_path="app/views.py",
        entry_block_id="bb_0",
        exit_block_id="bb_exit",
        blocks={"bb_0": b_entry, "bb_exit": b_exit},
        edges=[edge],
    )

    assert cfg.entry_block_id == "bb_0"
    succs = cfg.get_successors("bb_0")
    assert len(succs) == 1
    assert succs[0][0].id == "bb_exit"
    assert succs[0][1].kind == BranchKind.UNCONDITIONAL


def test_guard_condition_and_refinement_fact():
    cond = GuardCondition(
        variable_name="user_id",
        predicate_op=PredicateOp.IS_INSTANCE,
        expected_value=True,
        argument_literal="int",
        raw_expression="isinstance(user_id, int)",
        line=5,
        col=8,
    )
    assert cond.variable_name == "user_id"
    assert cond.predicate_op == PredicateOp.IS_INSTANCE

    fact = RefinementFact(
        variable_name="user_id",
        refined_type="int",
        is_numeric_string=False,
        is_non_null=True,
        provenance_line=5,
    )

    constraint = PathConstraint(conditions=[cond])
    constraint.add_refinement(fact)
    assert constraint.feasibility == PathFeasibilityStatus.FEASIBLE
    assert constraint.has_refinement_for("user_id", lambda f: f.refined_type == "int")
    assert not constraint.has_refinement_for("user_id", lambda f: f.is_numeric_string)


def test_path_state_defaults():
    state = PathState(
        path_id="p_0",
        current_block_id="bb_0",
    )
    assert state.branch_depth == 0
    assert not state.is_terminated
    assert state.constraints.feasibility == PathFeasibilityStatus.FEASIBLE
