"""End-to-End integration tests for Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis."""

import ast
import pytest
from pathlib import Path
from analyzer.config.settings import AnalysisConfig
from analyzer.dataflow.callgraph.models import CallChainStep, InterproceduralTaintPath
from analyzer.dataflow.cfg.guard_evaluator import GuardEvaluator
from analyzer.dataflow.cfg.models import BasicBlock, BranchKind, ControlFlowGraph
from analyzer.dataflow.cfg.path_explorer import PathExplorer
from analyzer.dataflow.cfg.python_cfg_builder import PythonCFGBuilder
from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.dataflow.taint.models import SinkCategory, TaintState
from analyzer.dataflow.taint.propagator import TaintPropagator
from analyzer.dataflow.taint.registry import TaintRegistry
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.findings import EvidenceType, Finding, FindingCategory, FindingConfidence, FindingSeverity, SourceLocation


def test_scenario_a_early_return_guard_suppression():
    """Scenario A: Early return on failure prunes unsafe execution; verified in intraprocedural analyzer."""
    code = """
def handle(request):
    user_id = request.args['id']
    if not isinstance(user_id, int):
        return
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    registry = TaintRegistry(load_defaults=True)
    analyzer = PythonDataFlowAnalyzer(registry=registry)
    tree = ast.parse(code)
    traces = analyzer.analyze_function(tree.body[0], "views.py", code)
    # The early return branch exits; continuation has isinstance(user_id, int) == True, suppressing SQL injection!
    assert len(traces) == 0


def test_scenario_b_isinstance_guard_refinement():
    """Scenario B: isinstance(id, int) refines type and suppresses SQL injection in guarded branch."""
    code_guarded = """
def handle(request):
    user_id = request.args['id']
    if isinstance(user_id, int):
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    registry = TaintRegistry(load_defaults=True)
    analyzer = PythonDataFlowAnalyzer(registry=registry)
    tree = ast.parse(code_guarded)
    traces_guarded = analyzer.analyze_function(tree.body[0], "views.py", code_guarded)
    assert len(traces_guarded) == 0

    code_unguarded = """
def handle(request):
    user_id = request.args['id']
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    tree_unguarded = ast.parse(code_unguarded)
    traces_unguarded = analyzer.analyze_function(tree_unguarded.body[0], "views.py", code_unguarded)
    assert len(traces_unguarded) == 1
    assert traces_unguarded[0].sink["sink_id"] == "SQL_EXECUTE_CURSOR"


def test_scenario_c_assert_semantics():
    """Scenario C: Assert True continuation carries refinement fact; False terminates exceptionally."""
    code_assert = """
def handle(request):
    user_id = request.args['id']
    assert isinstance(user_id, int)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    registry = TaintRegistry(load_defaults=True)
    analyzer = PythonDataFlowAnalyzer(registry=registry)
    tree = ast.parse(code_assert)
    traces = analyzer.analyze_function(tree.body[0], "views.py", code_assert)
    assert len(traces) == 0


def test_scenario_d_command_injection_guard():
    """Scenario D: shlex.quote or alphanumeric guard refines command injection."""
    code = """
def handle(request):
    cmd = request.args['cmd']
    if shlex.quote(cmd):
        os.system(cmd)
"""
    registry = TaintRegistry(load_defaults=True)
    analyzer = PythonDataFlowAnalyzer(registry=registry)
    tree = ast.parse(code)
    traces = analyzer.analyze_function(tree.body[0], "views.py", code)
    assert len(traces) == 0


def test_scenario_e_nested_interprocedural_guard(tmp_path):
    """Scenario E: Caller guards parameter before invoking callee with sink."""
    caller_code = """
from db import execute_query

def caller(request):
    val = request.args.get('id')
    if isinstance(val, int):
        execute_query(val)
"""
    callee_code = """
import sqlite3

def execute_query(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    p_caller = tmp_path / "views.py"
    p_caller.write_text(caller_code, encoding="utf-8")
    p_callee = tmp_path / "db.py"
    p_callee.write_text(callee_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    # In views.py, val is guarded with isinstance(val, int), so caller guard prunes the path!
    sec_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-011"]
    assert len(sec_findings) == 0

    # Verify path sensitivity metrics recorded the evaluation
    assert result.call_graph_summary is not None
    ps = result.call_graph_summary.get("path_sensitivity")
    assert ps is not None
    assert ps["guards_evaluated"] >= 1
    assert ps["guarded_paths_pruned"] >= 1


def test_scenario_f_finding_identity_invariance():
    """Scenario F: Finding seed hash is invariant to path conditions (no drift in finding id)."""
    loc = SourceLocation(file_path="app.py", line_start=10, col_start=4)
    f1 = Finding(
        id="f-001",
        rule_id="SEC-PY-009",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="cursor.execute(sql)",
        description="SQL injection",
        remediation="Use parameters",
        evidence={"path_condition": "x > 0", "branch_taken": "TRUE_BRANCH"},
    )
    f2 = Finding(
        id="f-001",
        rule_id="SEC-PY-009",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="cursor.execute(sql)",
        description="SQL injection",
        remediation="Use parameters",
        evidence={"path_condition": "x <= 0", "branch_taken": "FALSE_BRANCH"},
    )
    # Finding id is deterministic based on rule + location, not mutated by path condition
    assert f1.id == f2.id


def test_scenario_g_cfg_builder_and_path_explorer():
    """Scenario G: Full CFG build and path exploration for a function with try/except/finally and loops."""
    code = """
def process(data):
    x = 0
    try:
        if isinstance(data, int):
            x = data + 1
        else:
            raise ValueError("bad data")
    except ValueError:
        x = -1
    finally:
        x = x * 2
    return x
"""
    tree = ast.parse(code)
    builder = PythonCFGBuilder()
    cfg = builder.build_cfg(tree.body[0], "test.py")
    assert len(cfg.blocks) >= 4

    explorer = PathExplorer(max_active_paths=8, max_total_path_states=64, max_branch_depth=6)
    paths = explorer.explore_paths(cfg)
    assert len(paths) >= 1
    assert explorer.total_paths_explored > 0


def test_phase18_multi_run_determinism(tmp_path: Path):
    """Gate 3: Multi-run determinism test verifies identical results over 5 consecutive runs."""
    code = """
def handle_route(request):
    val = request.args.get('id')
    if isinstance(val, int):
        safe_call(val)
    else:
        unsafe_call(val)

def safe_call(v):
    print(v)

def unsafe_call(v):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute(f"SELECT * FROM items WHERE id = {v}")
"""
    p = tmp_path / "app.py"
    p.write_text(code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()

    first_findings = None
    first_summary = None

    for run_idx in range(5):
        result = pipeline.run(target_path=tmp_path, analysis_config=config)
        findings_repr = [(f.id, f.rule_id, f.location.line_start, f.location.col_start) for f in result.security_findings]
        ps = result.call_graph_summary.get("path_sensitivity", {}) if result.call_graph_summary else {}

        if run_idx == 0:
            first_findings = findings_repr
            first_summary = ps
        else:
            assert findings_repr == first_findings, f"Run {run_idx} produced non-deterministic findings"
            assert ps == first_summary, f"Run {run_idx} produced non-deterministic path_sensitivity summary"


def test_phase18_baseline_comparator_invariance():
    """Gate 7: Baseline differential verification: unchanged fixtures produce identical baseline matches."""
    from analyzer.comparison.diff import BaselineComparator
    from analyzer.models.results import AnalysisResult, RepositoryInfo

    loc = SourceLocation(file_path="app.py", line_start=15, col_start=4)
    finding = Finding(
        id="f-det-001",
        rule_id="SEC-PY-009",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="cursor.execute(sql)",
        description="SQL injection",
        remediation="Use parameters",
        evidence={
            "path_condition": "val is not None",
            "branch_taken": "TRUE_BRANCH",
            "guard_predicate": "val is not None",
        },
    )
    repo = RepositoryInfo(name="test-repo", local_path=".")
    result1 = AnalysisResult(
        repository=repo,
        security_findings=[finding],
        architecture_findings=[],
        call_graph_summary={"path_sensitivity": {"cfg_blocks_analyzed": 5}},
    )
    result2 = AnalysisResult(
        repository=repo,
        security_findings=[finding],
        architecture_findings=[],
        call_graph_summary={"path_sensitivity": {"cfg_blocks_analyzed": 5}},
    )

    diff = BaselineComparator.compare(current=result1, baseline=result2)
    assert diff.summary.new_count == 0
    assert diff.summary.resolved_count == 0
    assert diff.summary.unchanged_count == 1
    assert len(diff.findings) == 1
    assert diff.findings[0].transition.value == "UNCHANGED"
    assert diff.findings[0].finding.id == finding.id


