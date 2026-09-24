"""Unit tests for Phase 17 Bounded Alias and Points-To models."""

import pytest
from analyzer.dataflow.alias.models import (
    AbstractObject,
    AllocationSite,
    AliasBinding,
    AliasEnvironment,
    FieldKey,
    ObjectKind,
    PointsToSet,
)
from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeOrigin


def test_allocation_site_deterministic_id():
    site1 = AllocationSite(
        file_path="src/service.py",
        line=42,
        col=10,
        qualified_class_name="DatabaseConnection",
        enclosing_function="get_connection",
    )
    site2 = AllocationSite(
        file_path="src\\service.py",  # Windows backslash should normalize to forward slash
        line=42,
        col=10,
        qualified_class_name="DatabaseConnection",
        enclosing_function="get_connection",
    )
    assert site1.compute_id() == site2.compute_id()
    assert len(site1.compute_id()) == 16


def test_abstract_object_factories():
    tb = TypeBinding(
        type_name="DatabaseConnection",
        qualified_type_name="app.db.DatabaseConnection",
        confidence=TypeConfidence.KNOWN,
        origin=TypeOrigin.CONSTRUCTOR,
        source_file="src/service.py",
        line=15,
        col=4,
    )
    # Allocation site object
    obj_alloc = AbstractObject.create_allocation_site_object(
        type_binding=tb,
        file_path="src/service.py",
        line=15,
        col=4,
        enclosing_function="init_db",
    )
    assert obj_alloc.kind == ObjectKind.ALLOCATION_SITE
    assert obj_alloc.allocation_site is not None
    assert len(obj_alloc.object_id) == 16

    # Parameter object
    obj_param = AbstractObject.create_synthetic_parameter_object(
        fn_qualified_name="handle_request",
        param_index=0,
        param_name="req",
        type_binding=tb,
    )
    assert obj_param.kind == ObjectKind.PARAMETER_OBJECT
    assert obj_param.parameter_index == 0
    assert len(obj_param.object_id) == 16

    # Receiver self object
    obj_self = AbstractObject.create_receiver_self_object(
        enclosing_class="UserService",
        fn_qualified_name="UserService.process",
        type_binding=tb,
    )
    assert obj_self.kind == ObjectKind.RECEIVER_SELF
    assert len(obj_self.object_id) == 16

    # Unknown object
    obj_unk = AbstractObject.create_unknown_object(
        file_path="src/service.py",
        line=99,
        reason="dynamic_eval",
    )
    assert obj_unk.kind == ObjectKind.UNKNOWN_OBJECT
    assert len(obj_unk.object_id) == 16


def test_points_to_set_bounded_widening():
    # Empty set
    s0 = PointsToSet()
    assert s0.is_empty()
    assert len(s0) == 0

    # Add 4 distinct objects
    s = PointsToSet()
    for i in range(1, 5):
        s.add_object(f"obj_{i}", max_candidates=4)
    
    assert not s.is_empty()
    assert len(s) == 4
    assert not s.is_truncated

    # Adding a 5th object exceeds max_candidates=4 -> triggers truncation/widening flag
    s.add_object("obj_5", max_candidates=4)
    assert s.is_truncated
    assert s.is_ambiguous
    assert len(s) == 4  # Does not expand beyond bound


def test_points_to_set_join():
    s1 = PointsToSet(candidate_ids=["obj_1"])
    s2 = PointsToSet(candidate_ids=["obj_2"])
    
    joined = s1.merge(s2, max_candidates=4)
    assert len(joined) == 2
    assert "obj_1" in joined
    assert "obj_2" in joined
    assert not joined.is_truncated
    assert joined.is_ambiguous


def test_field_key():
    fk1 = FieldKey(object_id="obj_1", field_name="query")
    assert str(fk1.to_string_key()) == "obj_1.query"
    assert fk1.object_id == "obj_1"
    assert fk1.field_name == "query"


def test_alias_environment_bindings_and_queries():
    tb = TypeBinding(
        type_name="DbConn",
        qualified_type_name="app.db.DbConn",
        confidence=TypeConfidence.KNOWN,
        origin=TypeOrigin.CONSTRUCTOR,
        source_file="db.py",
        line=10,
    )
    obj = AbstractObject.create_allocation_site_object(tb, "db.py", 10, 0, "connect")
    
    env = AliasEnvironment()
    env.register_object(obj)
    env.set_points_to("conn", PointsToSet(candidate_ids=[obj.object_id]))
    
    pts_conn = env.get_points_to("conn")
    assert len(pts_conn) == 1
    
    # Alias assignment: cursor = conn
    env.set_points_to("cursor", pts_conn.copy())
    env.record_alias(
        AliasBinding(
            source_symbol="cursor",
            target_symbol="conn",
            confidence=TypeConfidence.KNOWN,
            line=12,
        )
    )
    
    assert env.may_alias("conn", "cursor")
    objs = env.get_objects_for("cursor")
    assert len(objs) == 1
    assert objs[0].object_id == obj.object_id


def test_alias_environment_join():
    tb = TypeBinding(
        type_name="A",
        qualified_type_name="app.A",
        confidence=TypeConfidence.KNOWN,
        origin=TypeOrigin.CONSTRUCTOR,
        source_file="t.py",
        line=10,
    )
    obj_a = AbstractObject.create_allocation_site_object(tb, "t.py", 10, 0, "fn")
    obj_b = AbstractObject.create_allocation_site_object(tb, "t.py", 20, 0, "fn")

    env1 = AliasEnvironment()
    env1.register_object(obj_a)
    env1.set_points_to("x", PointsToSet(candidate_ids=[obj_a.object_id]))

    env2 = AliasEnvironment()
    env2.register_object(obj_b)
    env2.set_points_to("x", PointsToSet(candidate_ids=[obj_b.object_id]))

    joined = env1.merge_branch(env2)
    pts = joined.get_points_to("x")
    assert len(pts) == 2
    assert obj_a.object_id in pts
    assert obj_b.object_id in pts
