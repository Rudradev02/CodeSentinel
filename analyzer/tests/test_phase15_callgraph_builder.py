"""Unit tests for CallGraphBuilder in Phase 15."""

from analyzer.dataflow.callgraph.graph_builder import CallGraphBuilder
from analyzer.dataflow.callgraph.models import CallResolutionType
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile


def test_build_call_graph_cross_file():
    code_utils = """
def build_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"
"""
    code_views = """
from utils.query import build_query

def handle_request(request):
    uid = request.args['id']
    q = build_query(uid)
    return q
"""
    pf_utils = ParsedFile(
        file_path="E:/repo/utils/query.py",
        relative_path="utils/query.py",
        language="PYTHON",
    )
    pf_views = ParsedFile(
        file_path="E:/repo/views.py",
        relative_path="views.py",
        language="PYTHON",
        imports=[
            ImportStatement(
                source_module="utils.query",
                imported_names=["build_query"],
                resolved_path="utils/query.py",
                dependency_category=ImportCategory.LOCAL,
            )
        ],
    )

    contents = {
        "utils/query.py": code_utils,
        "views.py": code_views,
    }

    builder = CallGraphBuilder()
    cg = builder.build_call_graph([pf_utils, pf_views], contents)

    assert len(cg.functions) == 2
    assert "utils.query.build_query" in cg.functions
    assert "views.handle_request" in cg.functions

    assert len(cg.edges) >= 1
    edge = next((e for e in cg.edges if e.callee_qualified_name == "utils.query.build_query"), None)
    assert edge is not None
    assert edge.caller_qualified_name == "views.handle_request"
    assert edge.resolution_type == CallResolutionType.RESOLVED_IMPORT


def test_build_call_graph_resource_limits():
    code = """
def f():
    g()
def g():
    pass
"""
    pf = ParsedFile(
        file_path="E:/repo/test.py",
        relative_path="test.py",
        language="PYTHON",
    )
    builder = CallGraphBuilder(max_call_edges=1)
    cg = builder.build_call_graph([pf], {"test.py": code})
    assert len(cg.edges) <= 1
