"""Unit tests for ContextManager and ConstantBranchEvaluator."""

import ast
import pytest
from analyzer.dataflow.callgraph.context_manager import ConstantBranchEvaluator, ContextManager
from analyzer.dataflow.types.models import CallContext, ConstantBool


def test_constant_branch_evaluator():
    code = "if sanitize: pass"
    stmt = ast.parse(code).body[0]
    test_node = stmt.test

    # When sanitize is True
    res_true = ConstantBranchEvaluator.evaluate_python_condition(
        test_node,
        param_names=["data", "sanitize"],
        constant_args={1: ConstantBool.TRUE},
    )
    assert res_true == ConstantBool.TRUE

    # When sanitize is False
    res_false = ConstantBranchEvaluator.evaluate_python_condition(
        test_node,
        param_names=["data", "sanitize"],
        constant_args={1: ConstantBool.FALSE},
    )
    assert res_false == ConstantBool.FALSE

    # When sanitize is unknown
    res_unk = ConstantBranchEvaluator.evaluate_python_condition(
        test_node,
        param_names=["data", "sanitize"],
        constant_args={},
    )
    assert res_unk == ConstantBool.UNKNOWN


def test_constant_branch_evaluator_not():
    code = "if not raw_mode: pass"
    stmt = ast.parse(code).body[0]
    test_node = stmt.test

    res = ConstantBranchEvaluator.evaluate_python_condition(
        test_node,
        param_names=["raw_mode"],
        constant_args={0: ConstantBool.TRUE},
    )
    assert res == ConstantBool.FALSE


def test_context_manager_bounds_and_widening():
    cm = ContextManager(max_k=2, max_contexts_per_function=2, max_total_contexts=10)
    root = CallContext.create_root_context()

    # Context 1
    c1, widened1 = cm.get_or_create_context(
        callee_qn="pkg.util.format",
        parent=root,
        call_site_id="site_1",
        arg_taints=[True],
    )
    assert widened1 is False
    assert c1.context_id != "WIDENED"

    # Context 2
    c2, widened2 = cm.get_or_create_context(
        callee_qn="pkg.util.format",
        parent=root,
        call_site_id="site_2",
        arg_taints=[False],
    )
    assert widened2 is False
    assert c2.context_id != "WIDENED"

    # Context 3: exceeds per-function cap of 2 -> triggers widening
    c3, widened3 = cm.get_or_create_context(
        callee_qn="pkg.util.format",
        parent=root,
        call_site_id="site_3",
        arg_taints=[True],
    )
    assert widened3 is True
    assert c3.context_id == "WIDENED"
    assert "MAX_CONTEXTS_PER_FUNCTION" in cm.truncation_reasons
