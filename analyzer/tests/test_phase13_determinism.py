"""Tests verifying semantic determinism in Phase 13 static analysis."""

import ast
import json
import pytest

from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.security.python.sec_py_009_sql_dataflow import RuleSecPy009


def test_finding_identity_and_evidence_determinism():
    """Verify that analyzing the same code multiple times produces identical finding identity and evidence."""
    code = """
def handle():
    user = request.args["user"]
    query = "SELECT * FROM accounts WHERE name=" + user
    cursor.execute(query)
"""
    rule = RuleSecPy009()

    run1 = rule.analyze("handler.py", code)
    run2 = rule.analyze("handler.py", code)

    assert len(run1) == 1
    assert len(run2) == 1

    f1 = run1[0]
    f2 = run2[0]

    # Finding UUIDv5 must match exactly
    assert f1.id == f2.id

    # Serialized evidence must match character for character
    ev1 = json.dumps(f1.evidence, sort_keys=True)
    ev2 = json.dumps(f2.evidence, sort_keys=True)
    assert ev1 == ev2
