"""Unit tests for PythonAliasExtractor."""

import ast
import pytest
from analyzer.dataflow.alias.python_alias_extractor import PythonAliasExtractor
from analyzer.dataflow.alias.models import ObjectKind


def _parse_fn(source: str) -> ast.FunctionDef:
    mod = ast.parse(source)
    return mod.body[0]  # type: ignore[return-value]


def test_python_alias_simple_assignment():
    code = """
def handler():
    conn = DatabaseClient()
    alias_conn = conn
    alias_conn.execute("SELECT 1")
"""
    fn = _parse_fn(code)
    extractor = PythonAliasExtractor()
    env, fsm = extractor.extract_function_aliases(fn, "src/db.py", fn_qualified_name="handler")

    assert env.may_alias("conn", "alias_conn")
    pts = env.get_points_to("alias_conn")
    assert pts is not None
    assert len(pts) == 1
    obj = pts.singleton_object()
    assert obj is not None
    assert obj.type_binding.type_name == "DatabaseClient"


def test_python_alias_field_write_and_read():
    code = """
def process(req):
    req.payload = "tainted"
    data = req.payload
"""
    fn = _parse_fn(code)
    extractor = PythonAliasExtractor()
    env, fsm = extractor.extract_function_aliases(fn, "src/api.py", fn_qualified_name="process")

    # req is a parameter object
    pts_req = env.get_points_to("req")
    assert pts_req is not None
    req_obj = pts_req.singleton_object()
    assert req_obj is not None
    assert req_obj.kind == ObjectKind.PARAMETER_OBJECT

    # field state should have req.payload
    field_entry = fsm.read_field("ROOT", env.field_key_for("req", "payload"))
    assert field_entry is not None
    assert fsm.get_field_edges_count() >= 1


def test_python_alias_branch_join():
    code = """
def setup(cond):
    if cond:
        runner = LocalRunner()
    else:
        runner = RemoteRunner()
    runner.execute("ls")
"""
    fn = _parse_fn(code)
    extractor = PythonAliasExtractor()
    env, fsm = extractor.extract_function_aliases(fn, "src/exec.py", fn_qualified_name="setup")

    pts = env.get_points_to("runner")
    assert pts is not None
    assert len(pts) == 2
    types = {o.type_binding.type_name for o in pts.objects}
    assert "LocalRunner" in types
    assert "RemoteRunner" in types


def test_python_alias_self_receiver():
    code = """
class Service:
    def execute(self, cmd):
        self.cmd = cmd
        self.runner = CommandRunner()
"""
    mod = ast.parse(code)
    cls_node = mod.body[0]
    fn = cls_node.body[0]  # type: ignore[attr-defined]

    extractor = PythonAliasExtractor()
    env, fsm = extractor.extract_function_aliases(
        fn, "src/service.py", enclosing_class="Service", fn_qualified_name="Service.execute"
    )

    pts_self = env.get_points_to("self")
    assert pts_self is not None
    self_obj = pts_self.singleton_object()
    assert self_obj is not None
    assert self_obj.kind == ObjectKind.RECEIVER_SELF
    assert self_obj.type_binding.type_name == "Service"
