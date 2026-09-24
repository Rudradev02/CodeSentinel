"""Unit tests for Phase 17 JS/TS Tree-sitter CST alias and points-to extractor."""

import pytest
from analyzer.dataflow.alias.jsts_alias_extractor import JSTSAliasExtractor
from analyzer.parsing.typescript_parser import TypeScriptParser


def _parse_ts_fn(code: str):
    p = TypeScriptParser()
    source_bytes = code.encode("utf-8")
    tree = p.ts_parser.parse(source_bytes)
    fn_node = tree.root_node.children[0]
    return fn_node, source_bytes


def test_ts_alias_new_and_assignment():
    code = """
function processData() {
    const repo = new UserRepository();
    const aliasRepo = repo;
    aliasRepo.find();
}
"""
    fn_node, source_bytes = _parse_ts_fn(code)
    extractor = JSTSAliasExtractor(
        repo_classes={"UserRepository": "src/repo/UserRepository"}
    )
    env, fsm = extractor.extract_function_aliases(fn_node, source_bytes, "src/index.ts")

    assert env.may_alias("repo", "aliasRepo")
    pts = env.get_points_to("aliasRepo")
    assert pts is not None
    assert len(pts) == 1
    objs = env.get_objects_for("aliasRepo")
    assert len(objs) == 1
    assert objs[0].type_binding.type_name == "UserRepository"


def test_ts_property_write_and_read():
    code = """
function handleRequest(req) {
    req.body = "user_input";
    const data = req.body;
}
"""
    fn_node, source_bytes = _parse_ts_fn(code)
    extractor = JSTSAliasExtractor()
    env, fsm = extractor.extract_function_aliases(fn_node, source_bytes, "src/handler.ts")

    pts_req = env.get_points_to("req")
    assert pts_req is not None
    assert len(pts_req) == 1
    assert fsm.get_field_edges_count() >= 1


def test_ts_branch_join():
    code = """
function initClient(cond) {
    let client;
    if (cond) {
        client = new LocalClient();
    } else {
        client = new RemoteClient();
    }
}
"""
    fn_node, source_bytes = _parse_ts_fn(code)
    extractor = JSTSAliasExtractor()
    env, fsm = extractor.extract_function_aliases(fn_node, source_bytes, "src/client.ts")

    pts = env.get_points_to("client")
    assert pts is not None
    assert len(pts) == 2
    objs = env.get_objects_for("client")
    types = {o.type_binding.type_name for o in objs}
    assert "LocalClient" in types
    assert "RemoteClient" in types
