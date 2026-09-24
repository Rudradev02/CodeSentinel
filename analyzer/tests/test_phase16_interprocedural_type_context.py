"""Comprehensive unit and scenario tests for Phase 16 Type-Aware & Context-Sensitive Propagation."""

import ast
import pytest
from analyzer.dataflow.callgraph.models import (
    CallGraph,
    FunctionDefinition,
    FunctionSummary,
    ParameterDef,
    SummarySinkInvocation,
    TaintTransfer,
)
from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator
from analyzer.dataflow.taint.models import SinkCategory


@pytest.fixture
def repo_callgraph():
    # 1. Caller: handle_request in app/views.py
    f_caller = FunctionDefinition(
        id="fn-view-req",
        qualified_name="app.views.handle_request",
        file_path="app/views.py",
        language="PYTHON",
        name="handle_request",
        line_start=1,
        line_end=10,
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
    # 3. DatabaseClient.execute in app/db.py
    f_db = FunctionDefinition(
        id="fn-db-exec",
        qualified_name="app.db.DatabaseClient.execute",
        file_path="app/db.py",
        language="PYTHON",
        name="execute",
        line_start=1,
        line_end=10,
        is_method=True,
        class_name="DatabaseClient",
        module_path="app.db",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="query", position=1)],
    )

    cg = CallGraph()
    cg.functions[f_caller.qualified_name] = f_caller
    cg.functions[f_repo.qualified_name] = f_repo
    cg.functions[f_db.qualified_name] = f_db
    return cg


def test_scenario_a_known_receiver_dispatch(repo_callgraph):
    # UserRepository.find_by_id internally executes an SQL query sink
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

    view_code = """
def handle_request():
    uid = request.args.get("id")
    repo = UserRepository()
    repo.find_by_id(uid)
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
    assert step.receiver_type == "app.repo.UserRepository"
    assert step.receiver_confidence == "KNOWN"
    assert step.context_id != "ROOT"


def test_scenario_d_contextual_sanitizer_separation(repo_callgraph):
    # clean_or_raw transfers taint to return
    summary_clean = FunctionSummary(
        qualified_name="app.utils.clean_or_raw",
        file_path="app/utils.py",
        parameters=[ParameterDef(name="m", position=0), ParameterDef(name="sanitize", position=1)],
        taint_transfers=[
            TaintTransfer(from_param_index=0, to_return=True)
        ],
    )
    summaries = {summary_clean.qualified_name: summary_clean}

    # In view_code, we use clean_or_raw with safe context and vulnerable context
    view_code = """
def handle_request():
    # Context 1: Safe constant
    safe_data = "hello"
    clean_or_raw(safe_data, sanitize=True)

    # Context 2: Vulnerable input
    user_input = request.args.get("q")
    raw = clean_or_raw(user_input, sanitize=False)
    cursor.execute(f"SELECT * FROM items WHERE name = '{raw}'")
"""
    # Register function clean_or_raw in callgraph
    f_clean = FunctionDefinition(
        id="fn-clean-or-raw",
        qualified_name="app.utils.clean_or_raw",
        file_path="app/utils.py",
        language="PYTHON",
        name="clean_or_raw",
        line_start=1,
        line_end=5,
        parameters=[ParameterDef(name="m", position=0), ParameterDef(name="sanitize", position=1)],
    )
    repo_callgraph.functions[f_clean.qualified_name] = f_clean

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
    assert p.call_chain[0].taint_action == "PROPAGATE_THROUGH"


def test_scenario_i_disable_type_inference_fallback(repo_callgraph):
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

    view_code = """
def handle_request():
    uid = request.args.get("id")
    repo = UserRepository()
    repo.find_by_id(uid)
"""
    # When type inference is disabled, repo.find_by_id cannot resolve receiver type
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
        disable_type_inference=True,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )
    # Should fall back cleanly without throwing exceptions
    assert isinstance(paths, list)
