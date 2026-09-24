"""Comprehensive tests for Phase 17 Bounded Alias, Points-To & Field-Sensitive Propagation."""

import ast
import pytest
from analyzer.dataflow.callgraph.models import (
    CallGraph,
    FunctionDefinition,
    FunctionSummary,
    ParameterDef,
    RichSummaryTransfer,
    SummarySinkInvocation,
    TaintTransfer,
    TransferDirection,
)
from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator
from analyzer.dataflow.taint.models import SinkCategory


@pytest.fixture
def repo_callgraph():
    # 1. Caller in app/views.py
    f_caller = FunctionDefinition(
        id="fn-view-req",
        qualified_name="app.views.handle_request",
        file_path="app/views.py",
        language="PYTHON",
        name="handle_request",
        line_start=1,
        line_end=15,
    )
    # 2. UserRepository.find_by_id in app/repo.py
    f_repo = FunctionDefinition(
        id="fn-repo-find",
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        language="PYTHON",
        name="find_by_id",
        line_start=1,
        line_end=10,
        is_method=True,
        class_name="UserRepository",
        module_path="app.repo",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
    )

    cg = CallGraph()
    cg.functions[f_caller.qualified_name] = f_caller
    cg.functions[f_repo.qualified_name] = f_repo
    return cg


def test_aliased_receiver_call_resolution(repo_callgraph):
    """Test call resolution and taint propagation through aliased receiver variable."""
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}

    view_code = """def handle_request():
    uid = request.args['id']
    repo = UserRepository()
    alias_repo = repo
    alias_repo.find_by_id(uid)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    assert len(paths) >= 1
    p = paths[0]
    assert p.category == SinkCategory.SQL_EXECUTE
    assert len(p.call_chain) == 1
    step = p.call_chain[0]
    assert step.callee_function == "app.repo.UserRepository.find_by_id"
    assert step.alias_path == "alias_repo -> repo"
    assert step.allocation_site is not None
    assert "ALLOC:" in step.allocation_site


def test_field_sensitive_taint_propagation(repo_callgraph):
    """Test taint write to an object field and read into a sink invocation."""
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}

    view_code = """def handle_request():
    payload = request.args['id']
    req = RequestContext()
    req.user_id = payload
    val = req.user_id
    repo = UserRepository()
    repo.find_by_id(val)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    assert len(paths) >= 1
    p = paths[0]
    assert p.category == SinkCategory.SQL_EXECUTE
    assert len(p.call_chain) >= 1


def test_field_sensitive_strong_update_clears_taint(repo_callgraph):
    """Test that a strong overwrite of a field with a safe value prevents false positive."""
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}

    view_code = """def handle_request():
    payload = request.args['id']
    req = RequestContext()
    req.user_id = payload
    req.user_id = "static_safe_id"
    val = req.user_id
    repo = UserRepository()
    repo.find_by_id(val)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    # Overwritten with static string -> should NOT trigger SQL_EXECUTE on val
    assert len(paths) == 0


def test_alias_semantic_summary_metrics(repo_callgraph):
    """Verify alias analysis metrics in get_semantic_summary()."""
    view_code = """def handle_request():
    conn = DatabaseClient()
    alias_c = conn
    alias_c.close()
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries={},
    )

    propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    summary = propagator.get_semantic_summary()
    assert "alias_analysis" in summary
    alias_metrics = summary["alias_analysis"]
    assert alias_metrics["abstract_objects_count"] >= 1
    assert alias_metrics["alias_bindings_count"] >= 1
