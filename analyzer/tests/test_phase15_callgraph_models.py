"""Unit tests for Phase 15 Call Graph foundation models."""

import pytest
from analyzer.dataflow.callgraph.models import (
    CallChainStep,
    CallEdge,
    CallGraph,
    CallResolutionType,
    FunctionDefinition,
    FunctionSummary,
    InterproceduralTaintPath,
    ParameterDef,
    ResolutionStats,
    SummarySanitizerApplication,
    SummarySinkInvocation,
    TaintTransfer,
    UnresolvedCall,
    UnresolvedReason,
)
from analyzer.dataflow.taint.models import SinkCategory


def test_function_definition_deterministic_id():
    id1 = FunctionDefinition.create_deterministic_id("utils/query.py", "utils.query.build_query", 10)
    id2 = FunctionDefinition.create_deterministic_id("utils/query.py", "utils.query.build_query", 10)
    id3 = FunctionDefinition.create_deterministic_id("utils/query.py", "utils.query.build_query", 11)
    assert id1 == id2
    assert id1 != id3


def test_function_definition_instantiation():
    param = ParameterDef(name="user_input", position=0, has_default=False, type_hint="str")
    fn = FunctionDefinition(
        id=FunctionDefinition.create_deterministic_id("views.py", "views.handle_request", 20),
        qualified_name="views.handle_request",
        file_path="views.py",
        language="PYTHON",
        name="handle_request",
        line_start=20,
        line_end=35,
        parameters=[param],
        is_method=False,
        is_async=False,
        decorators=["app.route"],
    )
    assert fn.qualified_name == "views.handle_request"
    assert len(fn.parameters) == 1
    assert fn.parameters[0].name == "user_input"


def test_call_edge_and_graph():
    edge_id = CallEdge.create_deterministic_id(
        "views.handle_request", "utils.query.build_query", "views.py", 25, 4
    )
    edge = CallEdge(
        id=edge_id,
        caller_qualified_name="views.handle_request",
        callee_qualified_name="utils.query.build_query",
        call_site_file="views.py",
        call_site_line=25,
        call_site_col=4,
        resolution_type=CallResolutionType.RESOLVED_IMPORT,
        argument_count=1,
    )
    stats = ResolutionStats(
        total_call_sites=1,
        resolved_local=0,
        resolved_import=1,
        unresolved=0,
        resolution_rate=1.0,
    )
    graph = CallGraph(
        functions={},
        edges=[edge],
        unresolved_calls=[],
        resolution_stats=stats,
    )
    assert len(graph.edges) == 1
    assert graph.edges[0].resolution_type == CallResolutionType.RESOLVED_IMPORT
    assert graph.resolution_stats.resolution_rate == 1.0


def test_function_summary_serialization():
    transfer = TaintTransfer(
        from_param_index=0,
        to_return=True,
        to_sink_category=SinkCategory.SQL_EXECUTE,
        via_operations=["format_string"],
    )
    sink = SummarySinkInvocation(
        sink_id="SQL_EXECUTE",
        sink_category=SinkCategory.SQL_EXECUTE,
        receiving_param_index=0,
        line=15,
        is_parameterized=False,
    )
    summary = FunctionSummary(
        qualified_name="utils.query.build_query",
        file_path="utils/query.py",
        parameters=[ParameterDef(name="query", position=0)],
        taint_transfers=[transfer],
        sink_invocations=[sink],
        returns_tainted=True,
    )
    d = summary.model_dump()
    assert d["qualified_name"] == "utils.query.build_query"
    assert d["returns_tainted"] is True
    assert len(d["taint_transfers"]) == 1


def test_interprocedural_taint_path():
    step = CallChainStep(
        caller_function="views.handle_request",
        callee_function="utils.query.build_query",
        caller_file="views.py",
        callee_file="utils/query.py",
        call_site_line=25,
        call_site_col=4,
        argument_index=0,
        callee_param_name="user_input",
        taint_action="PROPAGATE_THROUGH",
    )
    path = InterproceduralTaintPath(
        source={"expression": "request.args['id']", "line": 22, "file_path": "views.py"},
        call_chain=[step],
        sink={"callee": "cursor.execute", "line": 28, "file_path": "views.py"},
        path_summary="request.args['id'] -> build_query() -> cursor.execute()",
        category=SinkCategory.SQL_EXECUTE,
        total_depth=2,
        files_involved=["views.py", "utils/query.py"],
    )
    assert path.flow_type == "INTER_PROCEDURAL_TAINT"
    assert len(path.call_chain) == 1
    assert path.total_depth == 2
    assert "utils/query.py" in path.files_involved
