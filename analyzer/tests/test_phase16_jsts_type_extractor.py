"""Unit tests for Phase 16 JS/TS Tree-sitter static type extractor."""

import pytest
from analyzer.dataflow.types.jsts_type_extractor import JSTSTypeExtractor
from analyzer.dataflow.types.models import TypeConfidence, TypeOrigin
from analyzer.parsing.typescript_parser import TypeScriptParser


def test_ts_new_expression_and_alias():
    code = """
function processData() {
    const repo = new UserRepository();
    const aliasRepo = repo;
}
"""
    p = TypeScriptParser()
    source_bytes = code.encode("utf-8")
    tree = p.ts_parser.parse(source_bytes)
    fn_node = tree.root_node.children[0]

    extractor = JSTSTypeExtractor(
        repo_classes={"UserRepository": "src/repo/UserRepository"}
    )
    env = extractor.extract_function_types(fn_node, source_bytes, "src/index.ts")

    repo_binding = env.get_type("repo")
    assert repo_binding is not None
    assert repo_binding.type_name == "UserRepository"
    assert repo_binding.confidence == TypeConfidence.KNOWN
    assert repo_binding.origin == TypeOrigin.CONSTRUCTOR

    alias_binding = env.get_type("aliasRepo")
    assert alias_binding is not None
    assert alias_binding.type_name == "UserRepository"
    assert alias_binding.confidence == TypeConfidence.KNOWN
    assert alias_binding.origin == TypeOrigin.ALIAS


def test_ts_parameter_and_variable_annotations():
    code = """
function handleUser(repo: UserRepository) {
    const service: AuthService = getAuth();
}
"""
    p = TypeScriptParser()
    source_bytes = code.encode("utf-8")
    tree = p.ts_parser.parse(source_bytes)
    fn_node = tree.root_node.children[0]

    extractor = JSTSTypeExtractor(
        repo_classes={"UserRepository": "src/repo/UserRepository", "AuthService": "src/auth/AuthService"}
    )
    env = extractor.extract_function_types(fn_node, source_bytes, "src/index.ts")

    repo_param = env.get_type("repo")
    assert repo_param is not None
    assert repo_param.type_name == "UserRepository"
    assert repo_param.confidence == TypeConfidence.KNOWN
    assert repo_param.origin == TypeOrigin.TYPE_ANNOTATION

    service_var = env.get_type("service")
    assert service_var is not None
    assert service_var.type_name == "AuthService"
    assert service_var.confidence == TypeConfidence.KNOWN
