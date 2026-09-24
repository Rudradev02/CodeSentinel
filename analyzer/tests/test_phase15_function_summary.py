"""Tests for Phase 15 Workstream 15.5: Function Summary Generation."""

import ast
import pytest

from analyzer.dataflow.callgraph.discovery import FunctionDiscovery
from analyzer.dataflow.callgraph.models import FunctionDefinition, ParameterDef
from analyzer.dataflow.callgraph.summarizer import FunctionSummarizer
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.errors import AnalysisCancelledError
from analyzer.models.parse import ParsedFile


def test_python_param_to_return_summary():
    """Verify taint transfer from parameter to return via formatted string."""
    code = """
def build_query(user_input):
    return f"SELECT * FROM users WHERE id = {user_input}"
"""
    tree = ast.parse(code, filename="utils/query.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "utils/query.py")
    assert len(fns) == 1
    fn = fns[0]

    summarizer = FunctionSummarizer()
    summary = summarizer.summarize_function(fn, tree, code)

    assert summary.qualified_name == "utils.query.build_query"
    assert summary.is_summarized is True
    assert summary.returns_tainted is True
    assert summary.is_identity is False
    assert len(summary.taint_transfers) >= 1

    param_transfer = [t for t in summary.taint_transfers if t.from_param_index == 0 and t.to_return]
    assert len(param_transfer) == 1
    assert "FORMAT_STRING" in param_transfer[0].via_operations


def test_python_param_to_sink_summary():
    """Verify sink invocation detected when parameter flows to sink."""
    code = """
def execute_query(query):
    cursor.execute(query)
"""
    tree = ast.parse(code, filename="db.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "db.py")
    assert len(fns) == 1
    fn = fns[0]

    summarizer = FunctionSummarizer()
    summary = summarizer.summarize_function(fn, tree, code)

    assert summary.qualified_name == "db.execute_query"
    assert summary.is_summarized is True
    assert summary.returns_tainted is False
    assert len(summary.sink_invocations) >= 1

    sink = summary.sink_invocations[0]
    assert sink.sink_category == SinkCategory.SQL_EXECUTE
    assert sink.receiving_param_index == 0


def test_python_sanitizer_detection_summary():
    """Verify sanitizer application detected and recorded in summary."""
    code = """
def safe_id(val):
    clean = int(val)
    return clean
"""
    tree = ast.parse(code, filename="sanitize.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "sanitize.py")
    assert len(fns) == 1
    fn = fns[0]

    summarizer = FunctionSummarizer()
    summary = summarizer.summarize_function(fn, tree, code)

    assert summary.is_summarized is True
    assert summary.returns_tainted is False  # Sanitized, so returns clean
    assert len(summary.sanitizer_applications) >= 1
    assert summary.sanitizer_applications[0].sanitizer_id == "PY_INT_CONSTRAINT"
    assert summary.sanitizer_applications[0].applied_to_param_index == 0

    san_transfers = [t for t in summary.taint_transfers if t.sanitized_by]
    assert len(san_transfers) >= 1
    assert san_transfers[0].sanitized_by == "PY_INT_CONSTRAINT"


def test_python_identity_function():
    """Verify identity function (passthrough) is accurately identified."""
    code = """
def identity(x):
    return x
"""
    tree = ast.parse(code, filename="helpers.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "helpers.py")
    assert len(fns) == 1
    fn = fns[0]

    summarizer = FunctionSummarizer()
    summary = summarizer.summarize_function(fn, tree, code)

    assert summary.is_summarized is True
    assert summary.returns_tainted is True
    assert summary.is_identity is True


def test_javascript_function_summary():
    """Verify JavaScript function summary with parameter concatenation and DOM sink."""
    js_code = """
function buildCard(userInput) {
    return "<div>" + userInput + "</div>";
}

function render(html) {
    element.innerHTML = html;
}
"""
    discovery = FunctionDiscovery()
    fns = discovery.discover_jsts_functions(js_code, "app.js", "JAVASCRIPT")
    assert len(fns) == 2

    summarizer = FunctionSummarizer()
    from analyzer.parsing.javascript_parser import JavaScriptParser
    p = JavaScriptParser()
    tree = p.parser.parse(js_code.encode("utf-8"))
    root_node = tree.root_node
    assert root_node is not None

    summary_build = summarizer.summarize_function(fns[0], root_node, js_code)
    assert summary_build.returns_tainted is True
    assert len(summary_build.taint_transfers) >= 1
    assert summary_build.taint_transfers[0].to_return is True

    summary_render = summarizer.summarize_function(fns[1], root_node, js_code)
    assert summary_render.returns_tainted is False
    assert len(summary_render.sink_invocations) >= 1
    assert summary_render.sink_invocations[0].sink_category == SinkCategory.DOM_INJECTION


def test_recursive_function_handling():
    """Verify fixed-point iteration terminates gracefully on recursive functions."""
    code = """
def recurse(x):
    if len(x) > 0:
        return recurse(x)
    return x
"""
    parsed_files = [
        ParsedFile(
            file_path="rec.py",
            relative_path="rec.py",
            language="PYTHON",
            loc=5,
        )
    ]
    file_contents = {"rec.py": code}
    tree = ast.parse(code, filename="rec.py")

    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "rec.py")

    summarizer = FunctionSummarizer(max_summary_iterations=3)
    summaries = summarizer.summarize_all(
        functions=fns,
        parsed_files=parsed_files,
        file_contents=file_contents,
        ast_cache={"rec.py": tree},
    )

    assert "rec.recurse" in summaries
    rec_summary = summaries["rec.recurse"]
    assert rec_summary.is_summarized is True
    assert rec_summary.returns_tainted is True


def test_large_function_statement_bounds():
    """Verify functions exceeding max_function_body_statements are marked unsummarized."""
    # Create function with 600 statements
    lines = ["def huge_function(a):"]
    for i in range(600):
        lines.append(f"    x_{i} = a + {i}")
    lines.append("    return x_599")
    code = "\n".join(lines)

    tree = ast.parse(code, filename="huge.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "huge.py")

    summarizer = FunctionSummarizer(max_function_body_statements=500)
    summary = summarizer.summarize_function(fns[0], tree, code)

    assert summary.is_summarized is False
    assert summary.taint_transfers == []


def test_cooperative_cancellation():
    """Verify summarizer honors cancellation flag."""
    code = """
def test_fn(x):
    return x
"""
    tree = ast.parse(code, filename="test.py")
    discovery = FunctionDiscovery()
    fns = discovery.discover_python_functions(tree, "test.py")

    summarizer = FunctionSummarizer(is_cancelled=lambda: True)
    with pytest.raises(AnalysisCancelledError):
        summarizer.summarize_function(fns[0], tree, code)
