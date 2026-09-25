"""Unit tests for Phase 19 Function Contract Domain Models."""

import pytest
from analyzer.dataflow.cfg.models import RefinementFact
from analyzer.dataflow.contracts.models import (
    ConditionalTaintEffect,
    ContractVerificationStatus,
    EffectKind,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.taint.models import SinkCategory


def test_contract_enums():
    """Verify all Phase 19 contract enumeration members."""
    assert PreconditionKind.TYPE_REFINEMENT.value == "TYPE_REFINEMENT"
    assert PreconditionKind.FORMAT_REFINEMENT.value == "FORMAT_REFINEMENT"
    assert PreconditionKind.SANITIZER_CATEGORY.value == "SANITIZER_CATEGORY"
    assert PreconditionKind.NULLITY_REFINEMENT.value == "NULLITY_REFINEMENT"

    assert PostconditionTrigger.RETURN_EQUALS_TRUE.value == "RETURN_EQUALS_TRUE"
    assert PostconditionTrigger.RETURN_EQUALS_FALSE.value == "RETURN_EQUALS_FALSE"
    assert PostconditionTrigger.UNCONDITIONAL.value == "UNCONDITIONAL"
    assert PostconditionTrigger.PARAM_IS_NOT_NONE.value == "PARAM_IS_NOT_NONE"

    assert ContractVerificationStatus.SATISFIED.value == "SATISFIED"
    assert ContractVerificationStatus.VIOLATED.value == "VIOLATED"
    assert ContractVerificationStatus.UNKNOWN.value == "UNKNOWN"
    assert ContractVerificationStatus.INFEASIBLE.value == "INFEASIBLE"
    assert ContractVerificationStatus.WIDENED.value == "WIDENED"
    assert ContractVerificationStatus.TRUNCATED.value == "TRUNCATED"
    assert ContractVerificationStatus.UNRESOLVED.value == "UNRESOLVED"

    assert EffectKind.PROPAGATES_TAINT.value == "PROPAGATES_TAINT"
    assert EffectKind.CLEARS_TAINT.value == "CLEARS_TAINT"
    assert EffectKind.APPLIES_SANITIZER.value == "APPLIES_SANITIZER"


def test_summary_precondition_creation_and_properties():
    """Test SummaryPrecondition instantiation, defaults, and compatibility properties."""
    prec = SummaryPrecondition(
        target_param_index=1,
        target_param_name="uid",
        target_field_name="id",
        kind=PreconditionKind.TYPE_REFINEMENT,
        required_type="int",
        sink_category=SinkCategory.SQL_EXECUTE,
        raw_condition="isinstance(uid.id, int)",
        line=42,
    )

    assert prec.parameter_index == 1
    assert prec.parameter_name == "uid"
    assert prec.target_field_name == "id"
    assert prec.precondition_kind == PreconditionKind.TYPE_REFINEMENT
    assert prec.required_type == "int"
    assert prec.sink_category == SinkCategory.SQL_EXECUTE
    assert prec.raw_condition == "isinstance(uid.id, int)"
    assert prec.line == 42


def test_summary_postcondition_creation():
    """Test SummaryPostcondition instantiation with produced RefinementFact."""
    fact = RefinementFact(
        variable_name="token",
        refined_type="str",
        is_alphanumeric_string=True,
        provenance_line=15,
    )
    post = SummaryPostcondition(
        trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
        target_param_index=0,
        target_param_name="token",
        produced_refinement=fact,
        confidence="HIGH",
        provenance_line=15,
    )

    assert post.trigger == PostconditionTrigger.RETURN_EQUALS_TRUE
    assert post.target_param_index == 0
    assert post.target_param_name == "token"
    assert post.produced_refinement.is_alphanumeric_string is True
    assert post.confidence == "HIGH"


def test_conditional_taint_effect_creation():
    """Test ConditionalTaintEffect with sanitizers."""
    effect = ConditionalTaintEffect(
        governing_condition="sanitize == True",
        effect_kind=EffectKind.APPLIES_SANITIZER,
        parameter_index=0,
        clears_taint=False,
        sanitizer_applied="shlex.quote",
        confidence="HIGH",
    )

    assert effect.governing_condition == "sanitize == True"
    assert effect.effect_kind == EffectKind.APPLIES_SANITIZER
    assert effect.parameter_index == 0
    assert effect.sanitizer_applied == "shlex.quote"


def test_function_contract_hash_determinism_and_identity():
    """Test FunctionContract hash determinism and contract_id."""
    c1 = FunctionContract(
        qualified_name="app.services.validate_user",
        file_path="app/services.py",
        context_id="ctx_123",
        is_pure=True,
        preconditions=[
            SummaryPrecondition(
                target_param_index=0,
                target_param_name="user_id",
                kind=PreconditionKind.TYPE_REFINEMENT,
                required_type="int",
            )
        ],
        postconditions=[
            SummaryPostcondition(
                trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                target_param_index=0,
                target_param_name="user_id",
                produced_refinement=RefinementFact(
                    variable_name="user_id",
                    refined_type="int",
                ),
            )
        ],
    )
    hash1 = c1.compute_hash()
    assert hash1 is not None
    assert len(hash1) == 64  # SHA-256 hex string
    c1.contract_hash = hash1

    c2 = FunctionContract(
        qualified_name="app.services.validate_user",
        file_path="app/services.py",
        context_id="ctx_123",
        is_pure=True,
        preconditions=[
            SummaryPrecondition(
                target_param_index=0,
                target_param_name="user_id",
                kind=PreconditionKind.TYPE_REFINEMENT,
                required_type="int",
            )
        ],
        postconditions=[
            SummaryPostcondition(
                trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                target_param_index=0,
                target_param_name="user_id",
                produced_refinement=RefinementFact(
                    variable_name="user_id",
                    refined_type="int",
                ),
            )
        ],
    )
    hash2 = c2.compute_hash()
    assert hash1 == hash2
    assert c1.contract_id == c2.contract_id
    assert "app.services.validate_user" in c1.contract_id


def test_function_contract_serialization_roundtrip():
    """Verify that FunctionContract serializes cleanly to dict."""
    c = FunctionContract(
        qualified_name="pkg.utils.clean",
        file_path="pkg/utils.py",
        context_id="ROOT",
        is_pure=True,
    )
    c.contract_hash = c.compute_hash()
    data = c.model_dump()
    assert data["qualified_name"] == "pkg.utils.clean"
    assert data["file_path"] == "pkg/utils.py"
    assert data["context_id"] == "ROOT"
    assert data["is_pure"] is True
    assert data["contract_hash"] == c.contract_hash
