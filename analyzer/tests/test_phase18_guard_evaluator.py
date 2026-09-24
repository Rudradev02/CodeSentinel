"""Unit tests for Phase 18 Guard & Refinement Evaluator."""

import ast
import pytest
from analyzer.dataflow.cfg.guard_evaluator import GuardEvaluator
from analyzer.dataflow.cfg.models import PredicateOp


def test_isinstance_guard_refinement():
    evaluator = GuardEvaluator()
    tree = ast.parse("isinstance(uid, int)")
    conds, facts = evaluator.evaluate_python_condition(tree.body[0].value, True)

    assert len(conds) == 1
    assert conds[0].variable_name == "uid"
    assert conds[0].predicate_op == PredicateOp.IS_INSTANCE
    assert conds[0].argument_literal == "int"

    assert len(facts) == 1
    assert facts[0].variable_name == "uid"
    assert facts[0].refined_type == "int"
    assert facts[0].is_non_null is True


def test_isdigit_guard_refinement():
    evaluator = GuardEvaluator()
    tree = ast.parse("uid.isdigit()")
    conds, facts = evaluator.evaluate_python_condition(tree.body[0].value, True)

    assert len(conds) == 1
    assert conds[0].predicate_op == PredicateOp.IS_DIGIT
    assert len(facts) == 1
    assert facts[0].is_numeric_string is True


def test_anchored_regex_vs_unanchored():
    evaluator = GuardEvaluator()

    # Anchored regex produces format refinement
    anchored_tree = ast.parse("re.match(r'^[a-zA-Z0-9_]+$', token)")
    conds, facts = evaluator.evaluate_python_condition(anchored_tree.body[0].value, True)
    assert len(conds) == 1
    assert conds[0].predicate_op == PredicateOp.ANCHORED_REGEX
    assert len(facts) == 1
    assert facts[0].is_alphanumeric_string is True

    # Unanchored regex does NOT produce format refinement
    unanchored_tree = ast.parse("re.match(r'[a-zA-Z0-9_]+', token)")
    u_conds, u_facts = evaluator.evaluate_python_condition(unanchored_tree.body[0].value, True)
    assert len(u_conds) == 0
    assert len(u_facts) == 0


def test_category_specific_sanitizer():
    evaluator = GuardEvaluator()
    tree = ast.parse("shlex.quote(cmd)")
    conds, facts = evaluator.evaluate_python_condition(tree.body[0].value, True)

    assert len(facts) == 1
    assert facts[0].applicable_sanitizer_category == "COMMAND_EXECUTE"


def test_boolean_and_composition():
    evaluator = GuardEvaluator()
    tree = ast.parse("isinstance(uid, int) and uid is not None")
    conds, facts = evaluator.evaluate_python_condition(tree.body[0].value, True)

    assert len(conds) == 2
    assert any(c.predicate_op == PredicateOp.IS_INSTANCE for c in conds)
    assert any(c.predicate_op == PredicateOp.IS_NOT_NONE for c in conds)
    assert any(f.refined_type == "int" for f in facts)


def test_boolean_not_inversion():
    evaluator = GuardEvaluator()
    tree = ast.parse("not uid.isdigit()")
    conds, facts = evaluator.evaluate_python_condition(tree.body[0].value, True)

    assert len(conds) == 1
    assert conds[0].expected_value is False


def test_jsts_typeof_and_integer_guards():
    evaluator = GuardEvaluator()
    c1, f1 = evaluator.evaluate_jsts_condition("typeof x === 'number'", True)
    assert len(c1) == 1
    assert len(f1) == 1
    assert f1[0].refined_type == "number"

    c2, f2 = evaluator.evaluate_jsts_condition("Number.isInteger(count)", True)
    assert len(c2) == 1
    assert len(f2) == 1
    assert f2[0].is_numeric_string is True
