"""Unit tests for Phase 19 Contract Extractor for Python and JS/TS."""

import ast
import pytest
from analyzer.dataflow.contracts.extractor import ContractExtractor
from analyzer.dataflow.contracts.models import (
    PostconditionTrigger,
    PreconditionKind,
)
from analyzer.dataflow.taint.models import SinkCategory


def test_extract_python_direct_isinstance_contract():
    """Verify extraction of RETURN_EQUALS_TRUE postcondition from isinstance."""
    code = """
def is_valid_id(val):
    return isinstance(val, int)
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        func_node=fn_node,
        file_path="validator.py",
        qualified_name="validator.is_valid_id",
    )

    assert contract.qualified_name == "validator.is_valid_id"
    assert len(contract.postconditions) >= 1
    post = contract.postconditions[0]
    assert post.trigger == PostconditionTrigger.RETURN_EQUALS_TRUE
    assert post.target_param_index == 0
    assert post.target_param_name == "val"
    assert post.produced_refinement.refined_type == "int"
    assert contract.is_pure is True


def test_extract_python_branch_correlated_contract():
    """Verify extraction from if-branch return pattern."""
    code = """
def check_numeric(token):
    if token.isdigit():
        return True
    return False
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        func_node=fn_node,
        file_path="checker.py",
        qualified_name="checker.check_numeric",
    )

    assert contract.qualified_name == "checker.check_numeric"
    # Should extract RETURN_EQUALS_TRUE with is_numeric_string
    posts = [p for p in contract.postconditions if p.trigger == PostconditionTrigger.RETURN_EQUALS_TRUE]
    assert len(posts) >= 1
    assert posts[0].target_param_name == "token"
    assert posts[0].produced_refinement.is_numeric_string is True


def test_extract_python_sanitizer_return_contract():
    """Verify extraction of return sanitizer effect."""
    code = """
import html

def sanitize_html(content):
    return html.escape(content)
"""
    tree = ast.parse(code)
    fn_node = tree.body[1]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        func_node=fn_node,
        file_path="sanitizer.py",
        qualified_name="sanitizer.sanitize_html",
    )

    assert contract.qualified_name == "sanitizer.sanitize_html"
    posts = [p for p in contract.postconditions if p.applies_to_return]
    assert len(posts) >= 1
    assert posts[0].applicable_sanitizer_category == SinkCategory.DOM_INJECTION


def test_extract_python_precondition_from_internal_sink():
    """Verify extraction of precondition when function reaches a sink internally."""
    code = """
def run_query(uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = ContractExtractor()
    contract = extractor.extract_python_contract(
        func_node=fn_node,
        file_path="db.py",
        qualified_name="db.run_query",
    )

    assert len(contract.preconditions) >= 1
    prec = contract.preconditions[0]
    assert prec.target_param_name == "uid"
    assert prec.target_param_index == 0
    assert prec.kind == PreconditionKind.TYPE_REFINEMENT
    assert prec.required_type == "int"
    assert prec.sink_category == SinkCategory.SQL_EXECUTE


def test_extract_jsts_contract_simple():
    """Verify JS/TS contract extraction with tree-sitter node."""
    from analyzer.parsing.javascript_parser import JavaScriptParser
    js_code = b"""
function isValidNumber(val) {
    return typeof val === "number";
}
"""
    parser = JavaScriptParser()
    tree = parser.parser.parse(js_code)
    fn_node = tree.root_node.children[0]

    extractor = ContractExtractor()
    contract = extractor.extract_jsts_contract(
        func_node=fn_node,
        file_path="validator.js",
        qualified_name="validator.isValidNumber",
        source_bytes=js_code,
    )

    assert contract.qualified_name == "validator.isValidNumber"
    assert contract.file_path == "validator.js"
    assert contract.contract_hash is not None
