"""Tests for Phase 23 security property lattice join and non-laundering semantics."""

import pytest
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory


def test_property_state_immutability():
    state1 = SecurityPropertyState()
    state2 = state1.with_property(SecurityProperty.SQL_SAFE)

    assert state1.has_property(SecurityProperty.SQL_SAFE) is False
    assert state2.has_property(SecurityProperty.SQL_SAFE) is True
    assert state1 != state2


def test_lattice_join_identical_states():
    state1 = SecurityPropertyState(properties={SecurityProperty.SQL_SAFE})
    state2 = SecurityPropertyState(properties={SecurityProperty.SQL_SAFE})

    merged = SecurityPropertyState.join(state1, state2)
    assert merged.has_property(SecurityProperty.SQL_SAFE) is True
    assert merged.has_property(SecurityProperty.UNTRUSTED) is False


def test_lattice_join_unknown_never_laundered_to_safe():
    """Conservative join rule: If any branch carries UNKNOWN, UNKNOWN persists into the joined state."""
    safe_branch = SecurityPropertyState(properties={SecurityProperty.SQL_SAFE})
    unknown_branch = SecurityPropertyState(properties={SecurityProperty.UNKNOWN})

    merged = SecurityPropertyState.join(safe_branch, unknown_branch)
    assert merged.has_property(SecurityProperty.UNKNOWN) is True
    assert merged.is_safe_for_sink(SinkCategory.SQL_EXECUTE) is False


def test_lattice_join_one_branch_unsanitized():
    """If one branch sanitizes with SQL_SAFE and the other branch leaves input UNTRUSTED,
    the joined state MUST remain UNTRUSTED and NOT safe for SQL sink."""
    sanitized_branch = SecurityPropertyState(properties={SecurityProperty.SQL_SAFE})
    unsanitized_branch = SecurityPropertyState(properties={SecurityProperty.UNTRUSTED})

    merged = SecurityPropertyState.join(sanitized_branch, unsanitized_branch)
    assert merged.has_property(SecurityProperty.UNTRUSTED) is True
    assert merged.has_property(SecurityProperty.SQL_SAFE) is False
    assert merged.is_safe_for_sink(SinkCategory.SQL_EXECUTE) is False


def test_lattice_join_disjoint_properties():
    """Merging a branch that is SQL_SAFE with a branch that is COMMAND_SAFE preserves neither as universally safe."""
    sql_branch = SecurityPropertyState(properties={SecurityProperty.SQL_SAFE})
    cmd_branch = SecurityPropertyState(properties={SecurityProperty.COMMAND_SAFE})

    merged = SecurityPropertyState.join(sql_branch, cmd_branch)
    assert merged.has_property(SecurityProperty.SQL_SAFE) is False
    assert merged.has_property(SecurityProperty.COMMAND_SAFE) is False
