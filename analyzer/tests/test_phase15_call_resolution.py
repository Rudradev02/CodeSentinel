"""Unit tests for CallResolver in Phase 15."""

import pytest

from analyzer.dataflow.callgraph.models import (
    CallResolutionType,
    FunctionDefinition,
    ParameterDef,
    UnresolvedReason,
)
from analyzer.dataflow.callgraph.resolver import CallResolver
from analyzer.models.parse import ImportCategory, ImportStatement


def _make_fn(file_path: str, qn: str, name: str, is_method: bool = False, class_name: str = None) -> FunctionDefinition:
    mod = qn.rsplit(".", 2)[0] if is_method else qn.rsplit(".", 1)[0]
    return FunctionDefinition(
        id=FunctionDefinition.create_deterministic_id(file_path, qn, 10),
        qualified_name=qn,
        file_path=file_path,
        language="PYTHON",
        name=name,
        line_start=10,
        line_end=20,
        parameters=[ParameterDef(name="x", position=0)],
        is_method=is_method,
        class_name=class_name,
        module_path=mod,
    )


def test_resolve_local_method():
    f_caller = _make_fn("services/auth.py", "services.auth.AuthService.login", "login", is_method=True, class_name="AuthService")
    f_validate = _make_fn("services/auth.py", "services.auth.AuthService.validate", "validate", is_method=True, class_name="AuthService")

    resolver = CallResolver([f_caller, f_validate])
    edge, unres = resolver.resolve_call(
        caller=f_caller,
        callee_expr="self.validate(password)",
        line=15,
        col=8,
        arg_count=1,
        enclosing_class="AuthService",
    )
    assert unres is None
    assert edge is not None
    assert edge.resolution_type == CallResolutionType.RESOLVED_LOCAL
    assert edge.callee_qualified_name == "services.auth.AuthService.validate"


def test_resolve_local_function():
    f_caller = _make_fn("utils/strings.py", "utils.strings.clean", "clean")
    f_helper = _make_fn("utils/strings.py", "utils.strings.strip_tags", "strip_tags")

    resolver = CallResolver([f_caller, f_helper])
    edge, unres = resolver.resolve_call(
        caller=f_caller,
        callee_expr="strip_tags(text)",
        line=12,
        col=4,
        arg_count=1,
    )
    assert unres is None
    assert edge is not None
    assert edge.resolution_type == CallResolutionType.RESOLVED_LOCAL
    assert edge.callee_qualified_name == "utils.strings.strip_tags"


def test_resolve_imported_function():
    f_caller = _make_fn("views.py", "views.handle_request", "handle_request")
    f_query = _make_fn("utils/query.py", "utils.query.build_query", "build_query")

    imp = ImportStatement(
        source_module="utils.query",
        imported_names=["build_query"],
        resolved_path="utils/query.py",
        dependency_category=ImportCategory.LOCAL,
    )

    resolver = CallResolver([f_caller, f_query])
    edge, unres = resolver.resolve_call(
        caller=f_caller,
        callee_expr="build_query",
        line=25,
        col=4,
        arg_count=1,
        imports=[imp],
    )
    assert unres is None
    assert edge is not None
    assert edge.resolution_type == CallResolutionType.RESOLVED_IMPORT
    assert edge.callee_qualified_name == "utils.query.build_query"


def test_resolve_dynamic_call():
    f_caller = _make_fn("main.py", "main.run", "run")
    resolver = CallResolver([f_caller])
    edge, unres = resolver.resolve_call(
        caller=f_caller,
        callee_expr="getattr(obj, name)(arg)",
        line=30,
        col=4,
        arg_count=1,
        is_dynamic=True,
    )
    assert edge is None
    assert unres is not None
    assert unres.reason == UnresolvedReason.DYNAMIC_CALL


def test_resolve_external_call():
    f_caller = _make_fn("worker.py", "worker.process", "process")
    imp = ImportStatement(
        source_module="requests",
        imported_names=["get"],
        dependency_category=ImportCategory.EXTERNAL,
    )
    resolver = CallResolver([f_caller])
    edge, unres = resolver.resolve_call(
        caller=f_caller,
        callee_expr="requests.get",
        line=40,
        col=4,
        arg_count=1,
        imports=[imp],
    )
    assert edge is None
    assert unres is not None
    assert unres.reason == UnresolvedReason.EXTERNAL_MODULE
