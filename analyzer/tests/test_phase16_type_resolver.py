"""Unit tests for Phase 16 TypeAwareCallResolver."""

import pytest
from analyzer.dataflow.callgraph.models import (
    CallResolutionType,
    FunctionDefinition,
    ParameterDef,
    UnresolvedReason,
)
from analyzer.dataflow.callgraph.type_resolver import TypeAwareCallResolver
from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeEnvironment, TypeOrigin


@pytest.fixture
def sample_functions():
    f_caller = FunctionDefinition(
        id="fn-caller",
        qualified_name="app.views.handle_request",
        file_path="app/views.py",
        language="PYTHON",
        name="handle_request",
        line_start=10,
        line_end=20,
    )
    f_repo_method = FunctionDefinition(
        id="fn-repo-find",
        qualified_name="app.repositories.UserRepository.find_by_id",
        file_path="app/repositories.py",
        language="PYTHON",
        name="find_by_id",
        line_start=30,
        line_end=35,
        is_method=True,
        class_name="UserRepository",
        module_path="app.repositories",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="uid", position=1)],
    )
    f_db_exec = FunctionDefinition(
        id="fn-db-exec",
        qualified_name="app.db.DatabaseClient.execute",
        file_path="app/db.py",
        language="PYTHON",
        name="execute",
        line_start=50,
        line_end=55,
        is_method=True,
        class_name="DatabaseClient",
        module_path="app.db",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="query", position=1)],
    )
    return [f_caller, f_repo_method, f_db_exec]


def test_resolve_method_with_known_receiver(sample_functions):
    resolver = TypeAwareCallResolver(sample_functions)
    caller = sample_functions[0]

    env = TypeEnvironment()
    env.set_type(
        "repo",
        TypeBinding(
            type_name="UserRepository",
            qualified_type_name="app.repositories.UserRepository",
            confidence=TypeConfidence.KNOWN,
            origin=TypeOrigin.CONSTRUCTOR,
            source_file="app/views.py",
            line=11,
        ),
    )

    edge, unres = resolver.resolve_call(
        caller=caller,
        callee_expr="repo.find_by_id(uid)",
        line=12,
        col=4,
        arg_count=1,
        type_env=env,
    )

    assert unres is None
    assert edge is not None
    assert edge.callee_qualified_name == "app.repositories.UserRepository.find_by_id"
    assert edge.resolution_type == CallResolutionType.RESOLVED_IMPORT
    assert edge.is_method_call is True
    assert edge.receiver_type == "app.repositories.UserRepository"
    assert edge.receiver_confidence == TypeConfidence.KNOWN.value


def test_resolve_field_method_with_known_field_type(sample_functions):
    resolver = TypeAwareCallResolver(sample_functions)
    caller = sample_functions[0]

    env = TypeEnvironment()
    env.set_field_type(
        "self",
        "db",
        TypeBinding(
            type_name="DatabaseClient",
            qualified_type_name="app.db.DatabaseClient",
            confidence=TypeConfidence.KNOWN,
            origin=TypeOrigin.FIELD_ASSIGNMENT,
            source_file="app/views.py",
            line=5,
        ),
    )

    edge, unres = resolver.resolve_call(
        caller=caller,
        callee_expr="self.db.execute(sql)",
        line=15,
        col=4,
        arg_count=1,
        type_env=env,
    )

    assert unres is None
    assert edge is not None
    assert edge.callee_qualified_name == "app.db.DatabaseClient.execute"
    assert edge.receiver_type == "app.db.DatabaseClient"
    assert edge.receiver_confidence == TypeConfidence.KNOWN.value


def test_resolve_ambiguous_receiver(sample_functions):
    resolver = TypeAwareCallResolver(sample_functions)
    caller = sample_functions[0]

    env = TypeEnvironment()
    env.set_type(
        "repo",
        TypeBinding(
            type_name="AmbiguousRepo",
            qualified_type_name="AmbiguousRepo",
            confidence=TypeConfidence.AMBIGUOUS,
            origin=TypeOrigin.UNRESOLVED,
            source_file="app/views.py",
            line=11,
            candidate_types=["UserRepo", "AuditRepo"],
        ),
    )

    edge, unres = resolver.resolve_call(
        caller=caller,
        callee_expr="repo.save(data)",
        line=12,
        col=4,
        arg_count=1,
        type_env=env,
    )

    assert unres is not None
    assert unres.reason == UnresolvedReason.AMBIGUOUS
    assert edge is not None
    assert edge.receiver_confidence == TypeConfidence.AMBIGUOUS.value
    assert edge.candidate_targets == ["AuditRepo", "UserRepo"]  # Alphabetically sorted
