"""Tests verifying cooperative cancellation compatibility in Phase 13 data-flow analysis."""

import ast
import pytest
from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.models.errors import AnalysisCancelledError


def test_python_dataflow_honors_cancellation():
    """Verify that Python data-flow analysis raises AnalysisCancelledError when cancelled."""
    code = """
def long_function():
    a = request.args["a"]
    b = a
    c = b
    d = c
    e = d
    cursor.execute(e)
"""
    tree = ast.parse(code)

    cancelled = True
    analyzer = PythonDataFlowAnalyzer(is_cancelled=lambda: cancelled)

    with pytest.raises(AnalysisCancelledError):
        analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
