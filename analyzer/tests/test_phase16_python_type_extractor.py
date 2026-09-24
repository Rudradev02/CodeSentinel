"""Unit tests for Phase 16 Python static type extractor."""

import ast
import pytest
from analyzer.dataflow.types.models import TypeConfidence, TypeOrigin
from analyzer.dataflow.types.python_type_extractor import PythonTypeExtractor


def test_constructor_and_alias_inference():
    code = """
def handle_request():
    repo = UserRepository()
    alias_repo = repo
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = PythonTypeExtractor(
        repo_classes={"UserRepository": "app.repositories.UserRepository"}
    )
    env = extractor.extract_function_types(fn_node, "app/views.py")

    repo_binding = env.get_type("repo")
    assert repo_binding is not None
    assert repo_binding.type_name == "UserRepository"
    assert repo_binding.qualified_type_name == "app.repositories.UserRepository"
    assert repo_binding.confidence == TypeConfidence.KNOWN
    assert repo_binding.origin == TypeOrigin.CONSTRUCTOR

    alias_binding = env.get_type("alias_repo")
    assert alias_binding is not None
    assert alias_binding.type_name == "UserRepository"
    assert alias_binding.confidence == TypeConfidence.KNOWN
    assert alias_binding.origin == TypeOrigin.ALIAS


def test_parameter_and_field_binding():
    code = """
class UserService:
    def __init__(self, db: DatabaseClient):
        self.db = db
"""
    tree = ast.parse(code)
    cls_node = tree.body[0]
    init_fn = cls_node.body[0]

    extractor = PythonTypeExtractor(
        repo_classes={"DatabaseClient": "app.db.DatabaseClient", "UserService": "app.services.UserService"}
    )
    env = extractor.extract_function_types(
        init_fn,
        "app/services.py",
        enclosing_class="UserService",
    )

    # self
    self_binding = env.get_type("self")
    assert self_binding is not None
    assert self_binding.type_name == "UserService"
    assert self_binding.confidence == TypeConfidence.KNOWN

    # db parameter
    db_param = env.get_type("db")
    assert db_param is not None
    assert db_param.type_name == "DatabaseClient"
    assert db_param.confidence == TypeConfidence.KNOWN

    # self.db field
    field_binding = env.get_field_type("self", "db")
    assert field_binding is not None
    assert field_binding.type_name == "DatabaseClient"
    assert field_binding.confidence == TypeConfidence.KNOWN
    assert field_binding.origin == TypeOrigin.FIELD_ASSIGNMENT


def test_external_unresolved_type():
    code = """
def test_fn():
    req = ExternalRequest()
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    extractor = PythonTypeExtractor(repo_classes={})
    env = extractor.extract_function_types(fn_node, "app/views.py")

    req_binding = env.get_type("req")
    assert req_binding is not None
    assert req_binding.type_name == "ExternalRequest"
    assert req_binding.confidence == TypeConfidence.UNKNOWN
