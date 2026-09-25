"""Tests for Phase 20 exceptional contracts, return aliases, and container key extraction."""

import ast
import pytest
from analyzer.dataflow.contracts.extractor import ContractExtractor
from analyzer.dataflow.contracts.models import (
    ExceptionDisposition,
    ReturnAliasKind,
)


def test_exceptional_postcondition_extraction_python():
    """Verify that if-guards with raise statements synthesize ExceptionalPostconditions and normal-path refinements."""
    code = """
def validate_user_id(user_id):
    if not isinstance(user_id, int):
        raise TypeError("user_id must be integer")
    return user_id
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        fn_node=fn_node,
        file_path="pkg/validators.py",
        qualified_name="pkg.validators.validate_user_id",
    )

    # 1. Check exceptional postconditions
    assert len(contract.exceptional_postconditions) == 1
    ep = contract.exceptional_postconditions[0]
    assert ep.exception_type == "TypeError"
    assert ep.disposition == ExceptionDisposition.MUST_RAISE
    assert "not isinstance(user_id, int)" in ep.governing_condition

    # 2. Check normal return postconditions (negation of raise guard holds)
    int_posts = [
        p for p in contract.postconditions
        if getattr(p.produced_refinement, "refined_type", None) == "int"
    ]
    assert len(int_posts) >= 1

    # 3. Check return alias
    assert contract.return_alias_kind == ReturnAliasKind.ALIASED_PARAMETER
    assert contract.return_aliased_param_index == 0


def test_return_field_alias_extraction_python():
    """Verify that return obj.field extracts ReturnAliasKind.ALIASED_FIELD."""
    code = """
def extract_token(auth_obj):
    return auth_obj.token
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        fn_node=fn_node,
        file_path="pkg/auth.py",
        qualified_name="pkg.auth.extract_token",
    )

    assert contract.return_alias_kind == ReturnAliasKind.ALIASED_FIELD
    assert contract.return_aliased_param_index == 0
    assert contract.return_aliased_field == "token"


def test_container_key_refinements_extraction():
    """Verify dictionary return key refinements are captured in container_key_refinements."""
    code = """
def sanitize_payload(user_id, raw_name):
    return {
        "id": int(user_id),
        "name": html.escape(raw_name),
        "active": True
    }
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        fn_node=fn_node,
        file_path="pkg/cleaners.py",
        qualified_name="pkg.cleaners.sanitize_payload",
    )

    assert contract.return_alias_kind == ReturnAliasKind.NEW_ALLOCATION
    assert "id" in contract.container_key_refinements
    assert contract.container_key_refinements["id"].refined_type == "int"
    assert "name" in contract.container_key_refinements
    assert contract.container_key_refinements["name"].applicable_sanitizer_category == "DOM_INJECTION"
