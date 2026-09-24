"""Unit tests for PythonAliasExtractor."""

import ast
import pytest
from analyzer.dataflow.alias.python_alias_extractor import PythonAliasExtractor
from analyzer.dataflow.alias.models import FieldKey, ObjectKind


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
    assert len(pts) == 1
    objs = env.get_objects_for("alias_conn")
    assert len(objs) == 1
    assert objs[0].type_binding.type_name == "DatabaseClient"


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
    assert len(pts_req) == 1
    objs = env.get_objects_for("req")
    assert len(objs) == 1
    assert objs[0].kind == ObjectKind.PARAMETER_OBJECT

    # field state should have req.payload
    fk = FieldKey(object_id=objs[0].object_id, field_name="payload")
    field_entry = fsm.read_field("ROOT", fk)
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
    assert len(pts) == 2
    objs = env.get_objects_for("runner")
    types = {o.type_binding.type_name for o in objs}
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
    assert len(pts_self) == 1
    objs = env.get_objects_for("self")
    assert len(objs) == 1
    self_obj = objs[0]
    assert self_obj.kind == ObjectKind.RECEIVER_SELF
    assert self_obj.type_binding.type_name == "Service"
