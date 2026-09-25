"""Tests for Phase 20 deterministic refinement invalidation engine and epoch tracking."""

import pytest
from analyzer.dataflow.cfg.models import BasicBlock, PathConstraint, PathState, RefinementFact


def test_path_state_variable_epoch_invalidation():
    """Verify PathState variable invalidation increments epoch and purges stale facts."""
    state = PathState()
    assert state.var_epochs.get("x", 0) == 0

    # Add a refinement fact at epoch 0
    fact1 = RefinementFact(variable_name="x", refined_type="int", is_non_null=True, epoch=0)
    state.constraints.add_refinement_fact(fact1)

    valid_facts = state.get_valid_refinements("x")
    assert len(valid_facts) == 1
    assert valid_facts[0].refined_type == "int"

    # Invalidate variable x (simulates x = request.args['id'])
    new_epoch = state.invalidate_variable("x")
    assert new_epoch == 1
    assert state.var_epochs["x"] == 1

    # Stale facts with epoch 0 must no longer be returned
    assert len(state.get_valid_refinements("x")) == 0

    # Add a new fact at epoch 1
    fact2 = RefinementFact(variable_name="x", refined_type="str", is_non_null=True, epoch=1)
    state.constraints.add_refinement_fact(fact2)

    valid_facts_after = state.get_valid_refinements("x")
    assert len(valid_facts_after) == 1
    assert valid_facts_after[0].refined_type == "str"


def test_path_state_field_epoch_invalidation():
    """Verify PathState field invalidation increments epoch and filters out stale field facts."""
    state = PathState()
    fact1 = RefinementFact(variable_name="user.id", refined_type="int", epoch=0)
    state.constraints.add_refinement_fact(fact1)

    assert len(state.get_valid_refinements("user.id")) == 1

    # Invalidate user.id field
    new_epoch = state.invalidate_field("user", "id")
    assert new_epoch == 1
    assert state.field_epochs["user.id"] == 1

    # Stale field fact is now invalid
    assert len(state.get_valid_refinements("user.id")) == 0


def test_path_constraint_epoch_filtering():
    """Verify PathConstraint.has_refinement_for checks against current variable epoch."""
    constraint = PathConstraint()
    fact = RefinementFact(variable_name="token", refined_type="str", epoch=0)
    constraint.add_refinement_fact(fact)

    # Valid at epoch 0
    assert constraint.has_refinement_for("token", expected_type="str", current_epoch=0) is True

    # Invalid at epoch 1 (stale after reassignment)
    assert constraint.has_refinement_for("token", expected_type="str", current_epoch=1) is False


def test_path_state_branch_copy_epoch_isolation():
    """Verify branch copy isolates variable epochs between independent paths."""
    state1 = PathState()
    state1.var_epochs["x"] = 0
    fact = RefinementFact(variable_name="x", refined_type="int", epoch=0)
    state1.constraints.add_refinement_fact(fact)

    state2 = state1.branch_copy()
    assert state2.var_epochs["x"] == 0

    # Invalidate x in state2 only
    state2.invalidate_variable("x")
    assert state2.var_epochs["x"] == 1
    assert state1.var_epochs["x"] == 0

    # state1 still considers fact valid, state2 does not
    assert len(state1.get_valid_refinements("x")) == 1
    assert len(state2.get_valid_refinements("x")) == 0
