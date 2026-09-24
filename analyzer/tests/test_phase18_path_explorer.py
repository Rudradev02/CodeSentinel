"""Unit tests for Bounded Path Explorer and Feasibility Engine (Phase 18)."""

import ast
import pytest
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
from analyzer.dataflow.cfg.path_explorer import PathExplorer
from analyzer.dataflow.cfg.python_cfg_builder import PythonCFGBuilder
from analyzer.models.errors import AnalysisCancelledError


def test_feasibility_contradiction_opposite_polarities():
    """Verify that opposite polarities of the same condition are recognized as infeasible."""
    explorer = PathExplorer()
    constraints = PathConstraint()
    
    cond1 = GuardCondition(
        variable_name="x",
        predicate_op=PredicateOp.IS_DIGIT,
        expected_value=True,
        raw_expression="x.isdigit()",
    )
    cond2 = GuardCondition(
        variable_name="x",
        predicate_op=PredicateOp.IS_DIGIT,
        expected_value=False,
        raw_expression="x.isdigit()",
    )
    
    constraints.add_condition(cond1)
    assert not explorer.is_path_infeasible(constraints)
    
    constraints.add_condition(cond2)
    assert explorer.is_path_infeasible(constraints)
    assert "Opposite branch values" in constraints.contradiction_reason


def test_feasibility_contradiction_none_vs_not_none():
    """Verify that x is None AND x is not None is flagged as an infeasible contradiction."""
    explorer = PathExplorer()
    constraints = PathConstraint()
    
    c1 = GuardCondition(
        variable_name="val",
        predicate_op=PredicateOp.IS_NONE,
        expected_value=True,
        raw_expression="val is None",
    )
    c2 = GuardCondition(
        variable_name="val",
        predicate_op=PredicateOp.IS_NOT_NONE,
        expected_value=True,
        raw_expression="val is not None",
    )
    constraints.add_condition(c1)
    assert not explorer.is_path_infeasible(constraints)
    
    constraints.add_condition(c2)
    assert explorer.is_path_infeasible(constraints)
    assert "variable is None and is not None" in constraints.contradiction_reason


def test_feasibility_contradiction_disjoint_types():
    """Verify that isinstance(x, int) AND isinstance(x, str) is flagged as infeasible."""
    explorer = PathExplorer()
    constraints = PathConstraint()
    
    c1 = GuardCondition(
        variable_name="val",
        predicate_op=PredicateOp.IS_INSTANCE,
        expected_value=True,
        argument_literal="int",
        raw_expression="isinstance(val, int)",
    )
    c2 = GuardCondition(
        variable_name="val",
        predicate_op=PredicateOp.IS_INSTANCE,
        expected_value=True,
        argument_literal="str",
        raw_expression="isinstance(val, str)",
    )
    constraints.add_condition(c1)
    assert not explorer.is_path_infeasible(constraints)
    
    constraints.add_condition(c2)
    assert explorer.is_path_infeasible(constraints)
    assert "disjoint types" in constraints.contradiction_reason


def test_path_exploration_with_python_cfg():
    """Verify exploring a simple if/else Python function."""
    code = """
def test_fn(x):
    if isinstance(x, int):
        y = x + 1
        return y
    else:
        y = 0
        return y
"""
    func_node = ast.parse(code).body[0]
    builder = PythonCFGBuilder(file_path="test.py")
    cfg = builder.build_cfg(func_node, "test.test_fn")
    
    explorer = PathExplorer()
    paths = explorer.explore_paths(cfg, initial_var_states={"x": "TAINTED"})
    
    assert len(paths) >= 2
    # Check that at least one path has the int refinement
    has_int_refinement = any(
        any(f.refined_type == "int" for f in p.constraints.refinement_facts.get("x", []))
        for p in paths
    )
    assert has_int_refinement
    assert explorer.total_paths_explored >= 2


def test_early_exit_pruning():
    """Verify that early returns terminate paths and do not leak downstream."""
    code = """
def guard_fn(x):
    if not isinstance(x, int):
        return None
    sink(x)
    return x
"""
    func_node = ast.parse(code).body[0]
    builder = PythonCFGBuilder(file_path="test.py")
    cfg = builder.build_cfg(func_node, "test.guard_fn")
    
    explorer = PathExplorer()
    paths = explorer.explore_paths(cfg, initial_var_states={"x": "TAINTED"})
    
    # We should have the early exit path and the continuation path
    assert len(paths) >= 2
    for p in paths:
        assert p.is_terminated


def test_formal_lattice_join():
    """Verify lattice join behavior for taint, alias, fields, and refinement intersection."""
    explorer = PathExplorer()
    
    state_a = PathState(
        path_id="pa",
        current_block_id="bb_1",
        var_states={"x": "TAINTED", "y": "SANITIZED", "z": "UNTAINTED"},
        alias_bindings={"p": ["alloc_1"]},
        field_states={"obj.f": "TAINTED"},
    )
    state_a.constraints.add_refinement(
        RefinementFact(variable_name="x", refined_type="int", source_predicate="isinstance(x, int)")
    )
    state_a.constraints.add_refinement(
        RefinementFact(variable_name="y", is_numeric_string=True, source_predicate="y.isdigit()")
    )
    
    state_b = PathState(
        path_id="pb",
        current_block_id="bb_2",
        var_states={"x": "UNTAINTED", "y": "SANITIZED", "z": "UNTAINTED"},
        alias_bindings={"p": ["alloc_2"]},
        field_states={"obj.f": "UNTAINTED"},
    )
    # state_b has same refinement for x, but different for y
    state_b.constraints.add_refinement(
        RefinementFact(variable_name="x", refined_type="int", source_predicate="isinstance(x, int)")
    )
    state_b.constraints.add_refinement(
        RefinementFact(variable_name="y", refined_type="str", source_predicate="isinstance(y, str)")
    )
    
    joined = explorer.join_states(state_a, state_b, "bb_merge")
    
    # 1. Taint join: TAINTED | UNTAINTED -> TAINTED; SANITIZED & SANITIZED -> SANITIZED
    assert joined.var_states["x"] == "TAINTED"
    assert joined.var_states["y"] == "SANITIZED"
    assert joined.var_states["z"] == "UNTAINTED"
    
    # 2. Alias join: union
    assert set(joined.alias_bindings["p"]) == {"alloc_1", "alloc_2"}
    
    # 3. Field join: TAINTED | UNTAINTED -> TAINTED
    assert joined.field_states["obj.f"] == "TAINTED"
    
    # 4. Refinement facts: monotonic intersection: x has int on both, y differs
    assert "x" in joined.constraints.refinement_facts
    assert any(f.refined_type == "int" for f in joined.constraints.refinement_facts["x"])
    assert "y" not in joined.constraints.refinement_facts


def test_resource_budget_widening():
    """Verify widening when max_active_paths is constrained."""
    code = """
def branchy(a, b, c):
    if a:
        x = 1
    else:
        x = 2
    if b:
        y = 1
    else:
        y = 2
    if c:
        z = 1
    else:
        z = 2
    return x + y + z
"""
    func_node = ast.parse(code).body[0]
    builder = PythonCFGBuilder(file_path="test.py")
    cfg = builder.build_cfg(func_node, "test.branchy")
    
    # Set max_active_paths low to force widening
    explorer = PathExplorer(max_active_paths=2, max_total_path_states=20)
    paths = explorer.explore_paths(cfg)
    
    assert explorer.paths_widened > 0
    assert any(p.constraints.is_widened for p in paths)


def test_cancellation_checkpoint():
    """Verify that cancellation callback raises AnalysisCancelledError."""
    code = """
def loop_fn(n):
    for i in range(n):
        print(i)
"""
    func_node = ast.parse(code).body[0]
    builder = PythonCFGBuilder(file_path="test.py")
    cfg = builder.build_cfg(func_node, "test.loop_fn")
    
    cancelled = True
    explorer = PathExplorer(is_cancelled=lambda: cancelled)
    
    with pytest.raises(AnalysisCancelledError):
        explorer.explore_paths(cfg)
