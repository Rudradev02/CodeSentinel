"""Comprehensive tests for Phase 13 intraprocedural symbol, scope, and data-flow tracking."""

import ast
import pytest

from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.dataflow.symbol import DefinitionKind, Scope, ScopeKind, SymbolTable
from analyzer.dataflow.taint.models import SinkCategory, TaintState
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry


def test_deterministic_scope_identity():
    """Verify that scope IDs are strictly deterministic and contain no random UUIDs."""
    scope1 = Scope.create_deterministic_id("backend/views.py", ScopeKind.FUNCTION, "handle_request", 15, 4)
    scope2 = Scope.create_deterministic_id("backend/views.py", ScopeKind.FUNCTION, "handle_request", 15, 4)
    assert scope1 == scope2
    assert scope1 == "backend/views.py::FUNCTION::handle_request::15:4"
    assert "uuid" not in scope1.lower()


def test_symbol_table_and_shadowing():
    """Verify variable shadowing: inner scope definitions shadow outer without mutating outer state."""
    table = SymbolTable()

    # Module Scope
    mod_scope = Scope(
        id=Scope.create_deterministic_id("test.py", ScopeKind.MODULE, "<module>", 1, 0),
        name="<module>",
        qualified_name="<module>",
        kind=ScopeKind.MODULE,
        line_start=1,
        line_end=50,
    )
    mod_scope.add_definition("x", DefinitionKind.ASSIGNMENT, line=5, col=0, raw_expr="request.args['id']")
    table.add_scope(mod_scope)

    # Function Scope
    fn_scope = Scope(
        id=Scope.create_deterministic_id("test.py", ScopeKind.FUNCTION, "my_func", 10, 0),
        name="my_func",
        qualified_name="my_func",
        kind=ScopeKind.FUNCTION,
        line_start=10,
        line_end=30,
        parent_id=mod_scope.id,
    )
    fn_scope.add_definition("x", DefinitionKind.ASSIGNMENT, line=15, col=4, raw_expr="'safe_literal'")
    table.add_scope(fn_scope)

    # Resolving 'x' from inside function returns inner safe definition
    resolved_inner = table.resolve_symbol("x", from_scope_id=fn_scope.id, line=20)
    assert resolved_inner is not None
    assert resolved_inner.scope_id == fn_scope.id
    assert resolved_inner.raw_expr == "'safe_literal'"

    # Resolving 'x' from module scope still returns the outer definition
    resolved_outer = table.resolve_symbol("x", from_scope_id=mod_scope.id, line=35)
    assert resolved_outer is not None
    assert resolved_outer.scope_id == mod_scope.id
    assert resolved_outer.raw_expr == "request.args['id']"


def test_direct_and_chained_assignment():
    """Verify propagation across direct assignments: a = src; b = a; c = b."""
    code = """
def process():
    a = request.args["id"]
    b = a
    c = b
    cursor.execute(c)
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
    assert len(paths) == 1
    p = paths[0]
    assert p.source["symbol_name"] == "a"
    assert p.sink["tainted_argument"] == "c"
    assert len(p.propagation) >= 2


def test_binary_op_and_fstring_propagation():
    """Verify string concatenation (+) and f-string interpolation propagate taint."""
    code = """
def concat_query():
    uid = request.args["id"]
    q1 = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(q1)

def fstring_query():
    uid = request.args["id"]
    q2 = f"SELECT * FROM users WHERE id={uid}"
    cursor.execute(q2)
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
    assert len(paths) == 2


def test_tuple_unpacking():
    """Verify positional tuple unpacking: a, b = request.args['id'], 'safe'."""
    code = """
def unpack():
    a, b = request.args["id"], "safe"
    cursor.execute(a)  # Tainted
    cursor.execute(b)  # Untainted
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
    assert len(paths) == 1
    assert paths[0].sink["tainted_argument"] == "a"


def test_conditional_branch_conservative_merge():
    """Verify if/else merge: TAINTED | UNTAINTED = TAINTED."""
    code = """
def branch_merge(cond):
    if cond:
        val = request.args["id"]
    else:
        val = "default_safe"
    cursor.execute(val)
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
    assert len(paths) == 1
    assert paths[0].sink["tainted_argument"] == "val"


def test_loop_fixpoint_limit():
    """Verify loop variable tracking terminates without infinite recursion."""
    code = """
def loop_propagation():
    items = ["a", "b"]
    acc = "base"
    for item in items:
        acc = acc + request.args["token"]
    subprocess.run(acc)
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-010")
    assert len(paths) == 1
    assert paths[0].sink["tainted_argument"] == "acc"


def test_try_except_blocks():
    """Verify definitions in try and except blocks propagate conservatively."""
    code = """
def try_flow():
    try:
        val = request.args["id"]
    except Exception:
        val = "fallback"
    cursor.execute(val)
"""
    tree = ast.parse(code)
    analyzer = PythonDataFlowAnalyzer()
    paths = analyzer.analyze_file(tree, "test.py", target_rule_id="SEC-PY-009")
    assert len(paths) == 1
