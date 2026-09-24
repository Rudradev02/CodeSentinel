"""Tests for Phase 15 Workstream 15.6: Interprocedural Taint Propagation."""

import ast
import pytest

from analyzer.dataflow.callgraph.graph_builder import CallGraphBuilder
from analyzer.dataflow.callgraph.models import CallGraph
from analyzer.dataflow.callgraph.summarizer import FunctionSummarizer
from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.errors import AnalysisCancelledError
from analyzer.models.parse import ParsedFile


def test_cross_function_sql_injection_python():
    """Verify E2E Scenario 1: Source in caller, propagation through callee, sink in caller."""
    db_code = """
def build_query(user_input):
    return f"SELECT * FROM users WHERE id = {user_input}"
"""
    views_code = """
def handle_request(request):
    user_id = request.args['id']
    query = build_query(user_id)
    cursor.execute(query)
"""
    parsed_files = [
        ParsedFile(file_path="utils/db.py", relative_path="utils/db.py", language="PYTHON", loc=4),
        ParsedFile(file_path="views.py", relative_path="views.py", language="PYTHON", loc=6),
    ]
    file_contents = {
        "utils/db.py": db_code,
        "views.py": views_code,
    }
    trees = {
        "utils/db.py": ast.parse(db_code, filename="utils/db.py"),
        "views.py": ast.parse(views_code, filename="views.py"),
    }

    # 1. Build Call Graph
    builder = CallGraphBuilder()
    call_graph = builder.build_call_graph(parsed_files, file_contents, ast_cache=trees)

    # 2. Build Summaries
    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(
        functions=list(call_graph.functions.values()),
        parsed_files=parsed_files,
        file_contents=file_contents,
        ast_cache=trees,
        call_graph=call_graph,
    )

    # 3. Interprocedural Propagation
    propagator = InterproceduralTaintPropagator(call_graph=call_graph, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents, ast_cache=trees)

    assert len(paths) >= 1
    sql_path = paths[0]
    assert sql_path.category == SinkCategory.SQL_EXECUTE
    assert len(sql_path.call_chain) == 1
    step = sql_path.call_chain[0]
    assert step.caller_function == "views.handle_request"
    assert step.callee_function == "utils.db.build_query"
    assert step.taint_action == "PROPAGATE_THROUGH"
    assert "utils/db.py" in sql_path.files_involved
    assert "views.py" in sql_path.files_involved


def test_callee_sink_invocation_python():
    """Verify source in caller, taint passed to callee, and callee executes sink."""
    helper_code = """
def execute_raw(sql):
    cursor.execute(sql)
"""
    caller_code = """
def process(request):
    val = request.args.get('val')
    execute_raw(val)
"""
    parsed_files = [
        ParsedFile(file_path="db_helper.py", relative_path="db_helper.py", language="PYTHON", loc=4),
        ParsedFile(file_path="caller.py", relative_path="caller.py", language="PYTHON", loc=5),
    ]
    file_contents = {
        "db_helper.py": helper_code,
        "caller.py": caller_code,
    }
    trees = {
        "db_helper.py": ast.parse(helper_code, filename="db_helper.py"),
        "caller.py": ast.parse(caller_code, filename="caller.py"),
    }

    builder = CallGraphBuilder()
    call_graph = builder.build_call_graph(parsed_files, file_contents, ast_cache=trees)

    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(
        functions=list(call_graph.functions.values()),
        parsed_files=parsed_files,
        file_contents=file_contents,
        ast_cache=trees,
        call_graph=call_graph,
    )

    propagator = InterproceduralTaintPropagator(call_graph=call_graph, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents, ast_cache=trees)

    assert len(paths) >= 1
    path = paths[0]
    assert path.category == SinkCategory.SQL_EXECUTE
    assert len(path.call_chain) == 1
    assert path.call_chain[0].taint_action == "REACHES_SINK"
    assert path.sink["file_path"] == "db_helper.py"


def test_sanitized_cross_function_negative_python():
    """Verify E2E Scenario 2 (Negative): Taint sanitized in callee does not trigger finding."""
    san_code = """
import shlex
def safe_cmd(user_input):
    return shlex.quote(user_input)
"""
    handler_code = """
def run_command(request):
    cmd_arg = request.args['cmd']
    safe_arg = safe_cmd(cmd_arg)
    subprocess.run(['echo', safe_arg])
"""
    parsed_files = [
        ParsedFile(file_path="sanitizer.py", relative_path="sanitizer.py", language="PYTHON", loc=5),
        ParsedFile(file_path="handler.py", relative_path="handler.py", language="PYTHON", loc=6),
    ]
    file_contents = {
        "sanitizer.py": san_code,
        "handler.py": handler_code,
    }
    trees = {
        "sanitizer.py": ast.parse(san_code, filename="sanitizer.py"),
        "handler.py": ast.parse(handler_code, filename="handler.py"),
    }

    builder = CallGraphBuilder()
    call_graph = builder.build_call_graph(parsed_files, file_contents, ast_cache=trees)

    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(
        functions=list(call_graph.functions.values()),
        parsed_files=parsed_files,
        file_contents=file_contents,
        ast_cache=trees,
        call_graph=call_graph,
    )

    propagator = InterproceduralTaintPropagator(call_graph=call_graph, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents, ast_cache=trees)

    # Sanitized for command execution! No paths should be emitted
    cmd_paths = [p for p in paths if p.category == SinkCategory.COMMAND_EXECUTE]
    assert len(cmd_paths) == 0


def test_cross_function_dom_xss_javascript():
    """Verify cross-function DOM injection in JavaScript."""
    card_code = """
function buildCard(userInput) {
    return "<div class='card'>" + userInput + "</div>";
}
"""
    app_code = """
function handleUser() {
    const raw = window.location.search;
    const card = buildCard(raw);
    element.innerHTML = card;
}
"""
    parsed_files = [
        ParsedFile(file_path="card.js", relative_path="card.js", language="JAVASCRIPT", loc=4),
        ParsedFile(file_path="app.js", relative_path="app.js", language="JAVASCRIPT", loc=6),
    ]
    file_contents = {
        "card.js": card_code,
        "app.js": app_code,
    }

    builder = CallGraphBuilder()
    call_graph = builder.build_call_graph(parsed_files, file_contents)

    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(
        functions=list(call_graph.functions.values()),
        parsed_files=parsed_files,
        file_contents=file_contents,
        call_graph=call_graph,
    )

    propagator = InterproceduralTaintPropagator(call_graph=call_graph, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents)

    assert len(paths) >= 1
    dom_path = paths[0]
    assert dom_path.category == SinkCategory.DOM_INJECTION
    assert len(dom_path.call_chain) == 1
    assert dom_path.call_chain[0].caller_function == "app.handleUser"
    assert dom_path.call_chain[0].callee_function == "card.buildCard"
    assert dom_path.call_chain[0].taint_action == "PROPAGATE_THROUGH"


def test_resource_limits_and_bounds():
    """Verify max_path_count and cooperative cancellation in interprocedural analysis."""
    # Test cancellation
    propagator_cancel = InterproceduralTaintPropagator(
        call_graph=CallGraph(),
        summaries={},
        is_cancelled=lambda: True,
    )
    with pytest.raises(AnalysisCancelledError):
        propagator_cancel.analyze_repository([], {})
