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
        confidence=TypeConfidence.EXPLICIT,
        origin=TypeOrigin.CONSTRUCTOR_CALL,
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
    assert obj_alloc.object_id.startswith("ALLOC:")

    # Parameter object
    obj_param = AbstractObject.create_parameter_object(
        param_name="req",
        parameter_index=0,
        type_binding=tb,
        file_path="src/service.py",
        enclosing_function="handle_request",
    )
    assert obj_param.kind == ObjectKind.PARAMETER_OBJECT
    assert obj_param.parameter_index == 0
    assert obj_param.object_id.startswith("PARAM:")

    # Receiver self object
    obj_self = AbstractObject.create_receiver_self(
        class_name="UserService",
        file_path="src/service.py",
        enclosing_function="process",
    )
    assert obj_self.kind == ObjectKind.RECEIVER_SELF
    assert obj_self.object_id.startswith("SELF:")

    # Unknown object
    obj_unk = AbstractObject.create_unknown_object(
        reason="dynamic_eval",
        file_path="src/service.py",
        line=99,
    )
    assert obj_unk.kind == ObjectKind.UNKNOWN_OBJECT
    assert obj_unk.is_unknown()


def test_points_to_set_bounded_widening():
    tb = TypeBinding(type_name="ObjType", confidence=TypeConfidence.HEURISTIC, origin=TypeOrigin.SYNTACTIC_PATTERN)
    
    # Empty set
    s0 = PointsToSet.empty()
    assert s0.is_empty()
    assert len(s0) == 0

    # Add 4 distinct objects
    objects = [
        AbstractObject.create_allocation_site_object(tb, "file.py", i, 0, "fn")
        for i in range(1, 5)
    ]
    
    s = PointsToSet.empty(max_candidates=4)
    for obj in objects:
        s = s.add(obj)
    
    assert not s.is_empty()
    assert len(s) == 4
    assert not s.is_widened

    # Adding a 5th object exceeds max_candidates=4 -> triggers widening
    obj5 = AbstractObject.create_allocation_site_object(tb, "file.py", 5, 0, "fn")
    s_widened = s.add(obj5)
    
    assert s_widened.is_widened
    assert s_widened.may_alias_any()
    assert any(o.is_unknown() for o in s_widened.objects)


def test_points_to_set_join():
    tb = TypeBinding(type_name="ObjType", confidence=TypeConfidence.HEURISTIC, origin=TypeOrigin.SYNTACTIC_PATTERN)
    obj1 = AbstractObject.create_allocation_site_object(tb, "file.py", 10, 0, "fn")
    obj2 = AbstractObject.create_allocation_site_object(tb, "file.py", 20, 0, "fn")
    
    s1 = PointsToSet.singleton(obj1, max_candidates=3)
    s2 = PointsToSet.singleton(obj2, max_candidates=3)
    
    joined = s1.join(s2)
    assert len(joined) == 2
    assert obj1.object_id in joined.object_ids
    assert obj2.object_id in joined.object_ids
    assert not joined.is_widened


def test_field_key():
    fk1 = FieldKey(field_name="query")
    assert str(fk1) == "query"
    assert not fk1.is_index

    fk2 = FieldKey.from_index("0")
    assert fk2.is_index
    assert str(fk2) == "[0]"

    parsed = FieldKey.from_string("[items]")
    assert parsed.is_index
    assert parsed.field_name == "items"


def test_alias_environment_bindings_and_queries():
    tb = TypeBinding(type_name="DbConn", confidence=TypeConfidence.EXPLICIT, origin=TypeOrigin.CONSTRUCTOR_CALL)
    obj = AbstractObject.create_allocation_site_object(tb, "db.py", 10, 0, "connect")
    
    env = AliasEnvironment(function_name="main", file_path="main.py")
    env.bind_allocation("conn", obj)
    
    assert env.get_points_to("conn") is not None
    assert len(env.get_points_to("conn")) == 1
    
    # Alias assignment: cursor = conn
    env.bind_alias(source_var="conn", target_var="cursor", line=12)
    
    assert env.get_points_to("cursor") is not None
    assert env.get_points_to("cursor").object_ids == env.get_points_to("conn").object_ids
    assert env.may_alias("conn", "cursor")

    aliases_of_conn = env.get_aliases_for("conn")
    assert "cursor" in aliases_of_conn


def test_alias_environment_join():
    tb = TypeBinding(type_name="A", confidence=TypeConfidence.EXPLICIT, origin=TypeOrigin.CONSTRUCTOR_CALL)
    obj_a = AbstractObject.create_allocation_site_object(tb, "t.py", 10, 0, "fn")
    obj_b = AbstractObject.create_allocation_site_object(tb, "t.py", 20, 0, "fn")

    env1 = AliasEnvironment(function_name="branch_fn", file_path="t.py")
    env1.bind_allocation("x", obj_a)

    env2 = AliasEnvironment(function_name="branch_fn", file_path="t.py")
    env2.bind_allocation("x", obj_b)

    joined = env1.join(env2)
    pts = joined.get_points_to("x")
    assert pts is not None
    assert len(pts) == 2
    assert obj_a.object_id in pts.object_ids
    assert obj_b.object_id in pts.object_ids
