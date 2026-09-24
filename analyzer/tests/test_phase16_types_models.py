"""Unit tests for Phase 16 Type Inference and Call Context models."""

import pytest
from analyzer.dataflow.types.models import (
    CallContext,
    ConstantBool,
    TypeBinding,
    TypeConfidence,
    TypeEnvironment,
    TypeOrigin,
)


def test_type_confidence_and_origin():
    binding = TypeBinding(
        type_name="UserRepository",
        qualified_type_name="app.repositories.UserRepository",
        confidence=TypeConfidence.KNOWN,
        origin=TypeOrigin.CONSTRUCTOR,
        source_file="app/views.py",
        line=42,
    )
    assert binding.confidence == TypeConfidence.KNOWN
    assert binding.origin == TypeOrigin.CONSTRUCTOR
    assert binding.candidate_types == []


def test_type_environment_bindings():
    env = TypeEnvironment()
    binding = TypeBinding(
        type_name="DatabaseClient",
        qualified_type_name="db.DatabaseClient",
        confidence=TypeConfidence.KNOWN,
        origin=TypeOrigin.CONSTRUCTOR,
        source_file="app/services.py",
        line=10,
    )
    env.set_type("db", binding)
    assert env.get_type("db") == binding
    assert env.get_type("missing") is None

    # Field binding: self.db
    env.set_field_type("self", "db", binding)
    assert env.get_field_type("self", "db") == binding
    assert env.get_field_type("self", "other") is None


def test_call_context_push_and_bounding():
    root = CallContext.create_root_context()
    assert root.context_id == "ROOT"
    assert root.depth == 0

    c1 = CallContext.push_call_site(
        parent=root,
        call_site_id="cs1",
        arg_taints=[True, False],
        constant_args={1: ConstantBool.TRUE},
        receiver_type="app.UserRepository",
        max_k=2,
    )
    assert c1.depth == 1
    assert c1.call_string == ["cs1"]
    assert c1.context_id != "ROOT"

    c2 = CallContext.push_call_site(
        parent=c1,
        call_site_id="cs2",
        arg_taints=[True],
        max_k=2,
    )
    assert c2.depth == 2
    assert c2.call_string == ["cs1", "cs2"]

    # Exceeding k=2 truncates the oldest call site
    c3 = CallContext.push_call_site(
        parent=c2,
        call_site_id="cs3",
        arg_taints=[False],
        max_k=2,
    )
    assert c3.depth == 2
    assert c3.call_string == ["cs2", "cs3"]


def test_call_context_determinism():
    root = CallContext.create_root_context()
    c1a = CallContext.push_call_site(
        parent=root,
        call_site_id="site_1",
        arg_taints=[True, False],
        constant_args={0: ConstantBool.TRUE},
        receiver_type="Service",
        max_k=2,
    )
    c1b = CallContext.push_call_site(
        parent=root,
        call_site_id="site_1",
        arg_taints=[True, False],
        constant_args={0: ConstantBool.TRUE},
        receiver_type="Service",
        max_k=2,
    )
    assert c1a.context_id == c1b.context_id
