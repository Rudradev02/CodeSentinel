"""Unit tests for Phase 16 ContextSummaryManager and branch refinement."""

import ast
import pytest
from analyzer.dataflow.callgraph.context_summarizer import ContextSummaryManager
from analyzer.dataflow.callgraph.models import FunctionDefinition, ParameterDef
from analyzer.dataflow.types.models import CallContext, ConstantBool
from analyzer.dataflow.taint.registry import TaintRegistry


def test_contextual_sanitizer_branch_refinement():
    code = """
def clean_or_raw(data, sanitize=True):
    if sanitize:
        return escape(data)
    return data
"""
    tree = ast.parse(code)
    fn_node = tree.body[0]

    fn_def = FunctionDefinition(
        id="fn-clean-or-raw",
        qualified_name="app.utils.clean_or_raw",
        file_path="app/utils.py",
        language="PYTHON",
        name="clean_or_raw",
        line_start=2,
        line_end=6,
        parameters=[ParameterDef(name="data", position=0), ParameterDef(name="sanitize", position=1)],
    )

    manager = ContextSummaryManager(base_summaries={})

    # 1. Context A: sanitize=TRUE with tainted data
    ctx_safe = CallContext(
        context_id="ctx_safe",
        call_string=["site_1"],
        argument_taint_mask=[True, False],
        constant_args={1: ConstantBool.TRUE},
    )
    summary_safe = manager.specialize_python_summary(fn_def, fn_node, ctx_safe)
    # Under sanitize=TRUE, escape(data) is returned -> sanitized
    assert len(summary_safe.sanitizer_applications) == 1
    assert summary_safe.sanitizer_applications[0].sanitizer_id == "ESCAPE_FUNCTION"
    assert summary_safe.taint_transfers[0].sanitized_by == "ESCAPE_FUNCTION"

    # 2. Context B: sanitize=FALSE with tainted data
    ctx_vuln = CallContext(
        context_id="ctx_vuln",
        call_string=["site_2"],
        argument_taint_mask=[True, False],
        constant_args={1: ConstantBool.FALSE},
    )
    summary_vuln = manager.specialize_python_summary(fn_def, fn_node, ctx_vuln)
    # Under sanitize=FALSE, raw data is returned -> raw tainted transfer
    assert len(summary_vuln.sanitizer_applications) == 0
    assert summary_vuln.returns_tainted is True
    assert summary_vuln.taint_transfers[0].sanitized_by is None
