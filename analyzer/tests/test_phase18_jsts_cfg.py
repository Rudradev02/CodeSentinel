"""Unit tests for Phase 18 JavaScript / TypeScript Tree-sitter CFG Builder."""

import pytest
from analyzer.dataflow.cfg.jsts_cfg_builder import JSTSCFGBuilder
from analyzer.dataflow.cfg.models import BranchKind
from analyzer.parsing.typescript_parser import TypeScriptParser


def _parse_ts_fn(code: str):
    p = TypeScriptParser()
    source_bytes = code.encode("utf-8")
    tree = p.ts_parser.parse(source_bytes)
    fn_node = tree.root_node.children[0]
    return fn_node, source_bytes


def test_ts_cfg_sequential_and_return():
    code = """function greet(name: string): string {
    const msg = "Hello " + name;
    return msg;
}"""
    fn_node, source_bytes = _parse_ts_fn(code)
    builder = JSTSCFGBuilder()
    cfg = builder.build_cfg(fn_node, source_bytes, "src/greet.ts", "greet")

    assert cfg.function_qualified_name == "greet"
    assert cfg.entry_block_id in cfg.blocks
    assert cfg.exit_block_id in cfg.blocks
    # Check early exit on return block
    early_exits = [b for b in cfg.blocks.values() if b.is_early_exit]
    assert len(early_exits) >= 1


def test_ts_cfg_if_else_branching():
    code = """function validate(req: any) {
    if (!req.isValid) {
        throw new Error("Invalid");
    } else {
        const payload = req.data;
    }
    return "done";
}"""
    fn_node, source_bytes = _parse_ts_fn(code)
    builder = JSTSCFGBuilder()
    cfg = builder.build_cfg(fn_node, source_bytes, "src/validate.ts")

    true_edges = [e for e in cfg.edges if e.kind == BranchKind.TRUE_BRANCH]
    false_edges = [e for e in cfg.edges if e.kind == BranchKind.FALSE_BRANCH]
    assert len(true_edges) >= 1
    assert len(false_edges) >= 1

    # True branch has throw (early exit)
    true_target = cfg.blocks[true_edges[0].target_block_id]
    assert true_target.is_early_exit is True


def test_ts_cfg_try_catch():
    code = """function runQuery() {
    try {
        const res = db.query();
    } catch (e) {
        log(e);
    }
    return res;
}"""
    fn_node, source_bytes = _parse_ts_fn(code)
    builder = JSTSCFGBuilder()
    cfg = builder.build_cfg(fn_node, source_bytes, "src/query.ts")

    assert cfg.has_exceptions is True
    exc_blocks = [b for b in cfg.blocks.values() if b.is_exceptional]
    assert len(exc_blocks) >= 1
