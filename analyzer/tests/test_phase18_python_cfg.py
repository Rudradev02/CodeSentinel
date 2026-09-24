"""Unit tests for Phase 18 Python CFG Builder."""

import ast
import pytest
from analyzer.dataflow.cfg.models import BranchKind
from analyzer.dataflow.cfg.python_cfg_builder import PythonCFGBuilder
from analyzer.models.errors import AnalysisCancelledError


def test_sequential_cfg_construction():
    code = """def hello(name):
    greeting = "Hello, " + name
    return greeting
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(fn, "sample.py", "sample.hello")

    assert cfg.function_qualified_name == "sample.hello"
    assert cfg.entry_block_id in cfg.blocks
    assert cfg.exit_block_id in cfg.blocks
    # Entry -> Body -> Exit
    entry = cfg.blocks[cfg.entry_block_id]
    assert len(entry.successors) == 1
    body_id = entry.successors[0]
    body = cfg.blocks[body_id]
    assert body.is_early_exit is True
    assert cfg.exit_block_id in body.successors


def test_if_else_with_early_return():
    code = """def handle_request(req):
    if not req.is_valid():
        return "invalid"
    data = req.data
    return data
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(fn, "sample.py")

    # Verify branching edges from if decision block
    edges_from_decision = [e for e in cfg.edges if e.kind in (BranchKind.TRUE_BRANCH, BranchKind.FALSE_BRANCH)]
    assert len(edges_from_decision) == 2
    true_edge = next(e for e in edges_from_decision if e.kind == BranchKind.TRUE_BRANCH)
    false_edge = next(e for e in edges_from_decision if e.kind == BranchKind.FALSE_BRANCH)

    # True block has early return to exit
    true_block = cfg.blocks[true_edge.target_block_id]
    assert true_block.is_early_exit is True

    # False block continues to downstream statements
    false_block = cfg.blocks[false_edge.target_block_id]
    assert false_block.is_early_exit is False


def test_assert_statement_semantics():
    code = """def process_id(uid):
    assert uid.isdigit(), "UID must be numeric"
    query = "SELECT * FROM users WHERE id = " + uid
    return query
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(fn, "sample.py")

    # Assert creates True continuation and False AssertionError exit
    assert_edges = [e for e in cfg.edges if "uid.isdigit()" in (e.condition_expr or "")]
    assert len(assert_edges) >= 1
    true_edge = next(e for e in assert_edges if e.kind == BranchKind.TRUE_BRANCH)
    assert true_edge is not None


def test_try_except_finally_cfg():
    code = """def execute_db():
    try:
        data = fetch_input()
    except DatabaseError:
        log_error()
    finally:
        cleanup()
    return "done"
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(fn, "sample.py")

    assert cfg.has_exceptions is True
    # Exceptional edges present
    exc_edges = [e for e in cfg.edges if e.kind == BranchKind.EXCEPTIONAL]
    assert len(exc_edges) >= 1
    # Finally blocks marked
    finally_blocks = [b for b in cfg.blocks.values() if b.is_finally]
    assert len(finally_blocks) >= 1


def test_loop_cfg_semantics():
    code = """def sum_list(items):
    total = 0
    for x in items:
        total += x
    return total
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(fn, "sample.py")

    assert cfg.has_loops is True
    loop_back_edges = [e for e in cfg.edges if e.kind == BranchKind.LOOP_BACK]
    loop_exit_edges = [e for e in cfg.edges if e.kind == BranchKind.LOOP_EXIT]
    assert len(loop_back_edges) == 1
    assert len(loop_exit_edges) == 1


def test_cancellation():
    code = """def long_fn():
    x = 1
    y = 2
    return x + y
"""
    tree = ast.parse(code)
    fn = tree.body[0]
    builder = PythonCFGBuilder(is_cancelled=lambda: True)
    with pytest.raises(AnalysisCancelledError):
        builder.build_cfg(fn, "sample.py")
