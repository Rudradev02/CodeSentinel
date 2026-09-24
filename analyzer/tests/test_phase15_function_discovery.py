"""Unit tests for FunctionDiscovery in Phase 15."""

import ast
import pytest

from analyzer.dataflow.callgraph.discovery import FunctionDiscovery
from analyzer.models.parse import ParsedFile


def test_discover_python_functions_basic():
    code = """
def standalone(a, b=10) -> str:
    return "ok"

class MyService:
    def __init__(self, db):
        self.db = db

    async def get_user(self, user_id: int):
        return self.db.find(user_id)
"""
    tree = ast.parse(code)
    disco = FunctionDiscovery()
    fns = disco.discover_python_functions(tree, "services/user_service.py")

    assert len(fns) == 3
    # Check standalone
    f0 = next(f for f in fns if f.name == "standalone")
    assert f0.qualified_name == "services.user_service.standalone"
    assert f0.is_method is False
    assert len(f0.parameters) == 2
    assert f0.parameters[0].name == "a"
    assert f0.parameters[0].has_default is False
    assert f0.parameters[1].name == "b"
    assert f0.parameters[1].has_default is True

    # Check __init__
    f_init = next(f for f in fns if f.name == "__init__")
    assert f_init.qualified_name == "services.user_service.MyService.__init__"
    assert f_init.is_method is True
    assert f_init.is_constructor is True
    assert f_init.class_name == "MyService"

    # Check async method
    f_async = next(f for f in fns if f.name == "get_user")
    assert f_async.qualified_name == "services.user_service.MyService.get_user"
    assert f_async.is_async is True
    assert f_async.class_name == "MyService"


def test_discover_python_nested_functions():
    code = """
def outer():
    def inner(x):
        return x + 1
    return inner(5)
"""
    tree = ast.parse(code)
    disco = FunctionDiscovery()
    fns = disco.discover_python_functions(tree, "utils/math.py")
    assert len(fns) == 2
    names = {f.name for f in fns}
    assert "outer" in names
    assert "inner" in names


def test_discover_python_bounds():
    code = "\n".join(f"def func_{i}(): pass" for i in range(10))
    tree = ast.parse(code)
    disco = FunctionDiscovery(max_functions_per_file=5)
    fns = disco.discover_python_functions(tree, "many.py")
    assert len(fns) == 5


def test_discover_jsts_functions_basic():
    js_code = """
function processData(input) {
    return input.trim();
}

const formatQuery = (rawQuery) => {
    return "SELECT * FROM " + rawQuery;
};

class ApiClient {
    constructor(url) {
        this.url = url;
    }

    async fetchData(endpoint) {
        return fetch(this.url + endpoint);
    }
}
"""
    disco = FunctionDiscovery()
    fns = disco.discover_jsts_functions(js_code, "src/api.js", language="JAVASCRIPT")

    names = {f.name for f in fns}
    assert "processData" in names
    assert "formatQuery" in names
    assert "constructor" in names
    assert "fetchData" in names

    constructor_fn = next(f for f in fns if f.name == "constructor")
    assert constructor_fn.is_constructor is True
    assert constructor_fn.class_name == "ApiClient"


def test_discover_repository_cancellation():
    from analyzer.models.errors import AnalysisCancelledError
    pf = ParsedFile(
        file_path="E:/test/test.py",
        relative_path="test.py",
        language="PYTHON",
    )
    disco = FunctionDiscovery(is_cancelled=lambda: True)
    with pytest.raises(AnalysisCancelledError):
        disco.discover_repository_functions([pf], {"test.py": "def foo(): pass"})
