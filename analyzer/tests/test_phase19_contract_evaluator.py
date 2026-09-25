"""Unit tests for Phase 19 Contract Evaluator and Precondition Verification Engine."""

import pytest
from analyzer.dataflow.cfg.models import (
    PathConstraint,
    PathFeasibilityStatus,
    PathState,
    RefinementFact,
)
from analyzer.dataflow.contracts.evaluator import ContractEvaluator
from analyzer.dataflow.contracts.models import (
    ContractVerificationStatus,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.taint.models import SinkCategory


def test_verify_precondition_type_satisfied():
    """Verify that matching refined_type satisfies type precondition."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="uid",
        kind=PreconditionKind.TYPE_REFINEMENT,
        required_type="int",
    )
    facts = [
        RefinementFact(variable_name="user_id", refined_type="int")
    ]
    status = evaluator.verify_precondition(prec, facts, caller_arg_name="user_id")
    assert status == ContractVerificationStatus.SATISFIED


def test_verify_precondition_type_violated():
    """Verify that proven str type violates int requirement."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="uid",
        kind=PreconditionKind.TYPE_REFINEMENT,
        required_type="int",
    )
    facts = [
        RefinementFact(variable_name="user_id", refined_type="str")
    ]
    status = evaluator.verify_precondition(prec, facts, caller_arg_name="user_id")
    assert status == ContractVerificationStatus.VIOLATED


def test_verify_precondition_type_unknown():
    """Verify that absence of proof results in UNKNOWN (UNKNOWN != SAFE)."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="uid",
        kind=PreconditionKind.TYPE_REFINEMENT,
        required_type="int",
    )
    facts = []
    status = evaluator.verify_precondition(prec, facts, caller_arg_name="user_id")
    assert status == ContractVerificationStatus.UNKNOWN


def test_verify_precondition_format_satisfied():
    """Verify numeric string satisfies format refinement."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="val",
        kind=PreconditionKind.FORMAT_REFINEMENT,
        required_type="is_numeric_string",
    )
    facts = [
        RefinementFact(variable_name="token", is_numeric_string=True)
    ]
    status = evaluator.verify_precondition(prec, facts, caller_arg_name="token")
    assert status == ContractVerificationStatus.SATISFIED


def test_verify_precondition_sanitizer_category():
    """Verify category-specific sanitizer precondition matching."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="val",
        kind=PreconditionKind.SANITIZER_CATEGORY,
        required_sanitizer_category=SinkCategory.DOM_INJECTION,
    )
    # 1. Matching category
    facts_match = [
        RefinementFact(variable_name="val", applicable_sanitizer_category=SinkCategory.DOM_INJECTION)
    ]
    assert evaluator.verify_precondition(prec, facts_match, "val") == ContractVerificationStatus.SATISFIED

    # 2. Incompatible category
    facts_mismatch = [
        RefinementFact(variable_name="val", applicable_sanitizer_category=SinkCategory.COMMAND_EXECUTE)
    ]
    assert evaluator.verify_precondition(prec, facts_mismatch, "val") == ContractVerificationStatus.VIOLATED


def test_verify_precondition_path_state_statuses():
    """Verify that PathState infeasibility, widening, and truncation are strictly preserved."""
    evaluator = ContractEvaluator()
    prec = SummaryPrecondition(
        target_param_index=0,
        target_param_name="x",
        kind=PreconditionKind.TYPE_REFINEMENT,
        required_type="int",
    )

    # Infeasible path
    ps_infeasible = PathState(
        path_id="p_infeasible",
        current_block_id="bb_1",
        constraints=PathConstraint(feasibility=PathFeasibilityStatus.INFEASIBLE),
    )
    assert evaluator.verify_precondition(prec, ps_infeasible, "x") == ContractVerificationStatus.INFEASIBLE

    # Widened path
    ps_widened = PathState(
        path_id="p_widened",
        current_block_id="bb_1",
        constraints=PathConstraint(is_widened=True),
    )
    assert evaluator.verify_precondition(prec, ps_widened, "x") == ContractVerificationStatus.WIDENED

    # Truncated path
    ps_truncated = PathState(
        path_id="p_truncated",
        current_block_id="bb_1",
        constraints=PathConstraint(is_truncated=True),
    )
    assert evaluator.verify_precondition(prec, ps_truncated, "x") == ContractVerificationStatus.TRUNCATED


def test_bind_postconditions():
    """Verify binding of postconditions to caller arguments and return variables."""
    evaluator = ContractEvaluator()
    contract = FunctionContract(
        qualified_name="pkg.validate",
        file_path="pkg/val.py",
        postconditions=[
            SummaryPostcondition(
                trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                target_param_index=0,
                target_param_name="arg0",
                produced_refinement=RefinementFact(
                    variable_name="arg0",
                    refined_type="int",
                ),
            ),
            SummaryPostcondition(
                trigger=PostconditionTrigger.UNCONDITIONAL,
                applies_to_return=True,
                produced_refinement=RefinementFact(
                    variable_name="return",
                    applicable_sanitizer_category="DOM_INJECTION",
                ),
            ),
        ],
    )

    caller_state = PathState(path_id="p_caller", current_block_id="bb_caller")
    # Bind argument refinement
    bound_facts = evaluator.bind_postconditions(
        contract=contract,
        trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
        caller_arg_names=["user_param"],
        caller_path_state=caller_state,
        return_var_name="clean_result",
    )

    assert any(f.variable_name == "user_param" and f.refined_type == "int" for f in bound_facts)
    assert any(f.variable_name == "clean_result" and f.applicable_sanitizer_category == "DOM_INJECTION" for f in bound_facts)


def test_compose_path_conditions():
    """Test composition and contradiction detection."""
    evaluator = ContractEvaluator()

    # Simple conjunction
    c = evaluator.compose_path_conditions("x > 0", "y < 10")
    assert "x > 0" in c and "y < 10" in c

    # Deduplication
    assert evaluator.compose_path_conditions("x == 1", "x == 1") == "x == 1"

    # Direct contradiction
    res = evaluator.compose_path_conditions("x == 1", "not (x == 1)")
    assert res == "INFEASIBLE_CONTRADICTION"
