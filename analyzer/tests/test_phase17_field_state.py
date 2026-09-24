"""Unit tests for Phase 17 FieldStateMap and transfer functions."""

import pytest
from analyzer.dataflow.alias.field_state import FieldStateEntry, FieldStateMap
from analyzer.dataflow.alias.models import AbstractObject, FieldKey, PointsToSet
from analyzer.dataflow.taint.models import TaintState
from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeOrigin


def test_field_state_strong_update():
    fsm = FieldStateMap()
    fk = FieldKey(object_id="obj_1", field_name="data")
    
    # Initial write: untainted
    fsm.strong_update(
        context_id="ROOT",
        field_key=fk,
        points_to=PointsToSet.empty(),
        taint_state=TaintState.UNTAINTED,
    )
    res = fsm.read_field("ROOT", fk)
    assert res.taint_state == TaintState.UNTAINTED

    # Overwrite (strong update): tainted
    fsm.strong_update(
        context_id="ROOT",
        field_key=fk,
        points_to=PointsToSet.empty(),
        taint_state=TaintState.TAINTED,
    )
    res2 = fsm.read_field("ROOT", fk)
    assert res2.taint_state == TaintState.TAINTED


def test_field_state_weak_update():
    fsm = FieldStateMap()
    fk = FieldKey(object_id="obj_1", field_name="data")

    # Initial write: untainted
    fsm.weak_update(
        context_id="ROOT",
        field_key=fk,
        points_to=PointsToSet.empty(),
        taint_state=TaintState.UNTAINTED,
    )

    # Weak update with tainted: merges to TAINTED
    fsm.weak_update(
        context_id="ROOT",
        field_key=fk,
        points_to=PointsToSet.empty(),
        taint_state=TaintState.TAINTED,
    )
    res = fsm.read_field("ROOT", fk)
    assert res.taint_state == TaintState.TAINTED


def test_write_field_for_receiver_selection():
    fsm = FieldStateMap()
    
    # 1 receiver -> strong update
    fsm.write_field_for_receiver(
        context_id="ROOT",
        receiver_candidate_ids=["obj_singleton"],
        field_name="user",
        points_to=PointsToSet.empty(),
        taint_state=TaintState.TAINTED,
    )
    entry = fsm.read_field("ROOT", FieldKey(object_id="obj_singleton", field_name="user"))
    assert entry.taint_state == TaintState.TAINTED

    # 2 receivers -> weak update
    fsm.write_field_for_receiver(
        context_id="ROOT",
        receiver_candidate_ids=["obj_a", "obj_b"],
        field_name="role",
        points_to=PointsToSet.empty(),
        taint_state=TaintState.TAINTED,
    )
    entry_a = fsm.read_field("ROOT", FieldKey(object_id="obj_a", field_name="role"))
    entry_b = fsm.read_field("ROOT", FieldKey(object_id="obj_b", field_name="role"))
    assert entry_a.taint_state == TaintState.TAINTED
    assert entry_b.taint_state == TaintState.TAINTED


def test_field_state_branch_merge():
    fsm_then = FieldStateMap()
    fsm_else = FieldStateMap()
    
    fk = FieldKey(object_id="req_obj", field_name="input")
    
    fsm_then.strong_update("ROOT", fk, PointsToSet.empty(), TaintState.TAINTED)
    fsm_else.strong_update("ROOT", fk, PointsToSet.empty(), TaintState.UNTAINTED)

    merged = fsm_then.merge(fsm_else)
    res = merged.read_field("ROOT", fk)
    # TAINTED merged with UNTAINTED -> TAINTED
    assert res.taint_state == TaintState.TAINTED


def test_field_state_budget_overflow():
    fsm = FieldStateMap(max_fields_per_object=3)
    
    for i in range(3):
        fk = FieldKey(object_id="heavy_obj", field_name=f"field_{i}")
        fsm.strong_update("ROOT", fk, PointsToSet.empty(), TaintState.TAINTED)
    
    assert fsm.get_field_edges_count() == 3
    assert fsm.get_truncated_count() == 0

    # 4th field exceeds budget=3
    fk_overflow = FieldKey(object_id="heavy_obj", field_name="field_overflow")
    fsm.strong_update("ROOT", fk_overflow, PointsToSet.empty(), TaintState.TAINTED)
    
    assert fsm.get_truncated_count() == 1
    # Untracked field on overflow object returns UNKNOWN
    res = fsm.read_field("ROOT", fk_overflow)
    assert res.taint_state == TaintState.UNKNOWN
