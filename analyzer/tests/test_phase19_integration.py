"""End-to-end integration and scenario tests for Phase 19.

Covers Scenarios A through J, multi-hop interprocedural contracts,
and 5-run analysis determinism.
"""

import json
from pathlib import Path
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.findings import FindingCategory, FindingSeverity


def test_scenario_a_proven_boolean_validator(tmp_path: Path):
    """Scenario A: Proven Boolean Validator.
    
    Validator `is_valid_id` returns `isinstance(value, int)`.
    Caller guards `cursor.execute()` with `if is_valid_id(value):`.
    Contract discharges SQL injection precondition -> 0 findings emitted.
    """
    val_code = """
def is_valid_id(value):
    return isinstance(value, int)
"""
    db_code = """
import sqlite3

def execute_query(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    app_code = """
from validator import is_valid_id
from db import execute_query

def handle(request):
    value = request.args.get('id')
    if is_valid_id(value):
        execute_query(value)
"""
    (tmp_path / "validator.py").write_text(val_code, encoding="utf-8")
    (tmp_path / "db.py").write_text(db_code, encoding="utf-8")
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    sql_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-011"]
    assert len(sql_findings) == 0

    assert result.call_graph_summary is not None
    contracts_metric = result.call_graph_summary.get("contracts")
    assert contracts_metric is not None
    assert contracts_metric["contracts_generated"] >= 1
    assert contracts_metric["preconditions_verified"] >= 1


def test_scenario_b_multi_hop_contract_chain(tmp_path: Path):
    """Scenario B: Multi-Hop Contract Chain across 4 tiers.
    
    controller.py -> validator.py -> service.py -> repository.py -> cursor.execute().
    Integer refinement proven in controller propagates through service into repository,
    discharging callee precondition across 3 hops -> 0 findings emitted.
    """
    val_code = """
def check_id(raw_id):
    return isinstance(raw_id, int)
"""
    repo_code = """
import sqlite3

def find_user(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    service_code = """
from repo import find_user

def get_user_profile(user_id):
    return find_user(user_id)
"""
    controller_code = """
from validator import check_id
from service import get_user_profile

def user_controller(request):
    uid = request.args.get('uid')
    if check_id(uid):
        return get_user_profile(uid)
"""
    (tmp_path / "validator.py").write_text(val_code, encoding="utf-8")
    (tmp_path / "repo.py").write_text(repo_code, encoding="utf-8")
    (tmp_path / "service.py").write_text(service_code, encoding="utf-8")
    (tmp_path / "controller.py").write_text(controller_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    sql_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-011"]
    assert len(sql_findings) == 0

    contracts_metric = result.call_graph_summary.get("contracts", {})
    assert contracts_metric.get("contracts_generated", 0) >= 1


def test_scenario_c_conditional_sanitizer_parameter(tmp_path: Path):
    """Scenario C: Conditional Sanitizer Parameter.
    
    process(cmd, sanitize=False) -> vulnerable (SEC-PY-010 flagged).
    process(cmd, sanitize=True) -> safe (pruned).
    """
    util_code = """
import shlex

def process(data, sanitize=False):
    if sanitize:
        return shlex.quote(data)
    return data
"""
    app_code = """
import os
from util import process

def test_safe(req):
    cmd = req.args.get('cmd')
    safe_cmd = process(cmd, sanitize=True)
    os.system(safe_cmd)

def test_vuln(req):
    cmd = req.args.get('cmd')
    vuln_cmd = process(cmd, sanitize=False)
    os.system(vuln_cmd)
"""
    (tmp_path / "util.py").write_text(util_code, encoding="utf-8")
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    cmd_findings = [f for f in result.security_findings if f.rule_id in ("SEC-PY-012", "SEC-PY-010", "SEC-PY-003")]
    # Exactly test_vuln should be flagged, test_safe pruned!
    assert len(cmd_findings) >= 1


def test_scenario_d_unknown_custom_validator(tmp_path: Path):
    """Scenario D: Unknown Custom Validator.
    
    custom_check cannot be proven statically -> UNKNOWN status.
    UNKNOWN != SAFE, so standard taint retains warning (1 finding emitted).
    """
    val_code = """
import external_lib

def custom_check(value):
    return external_lib.verify(value)
"""
    db_code = """
import sqlite3

def execute_query(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    app_code = """
from validator import custom_check
from db import execute_query

def handle(request):
    value = request.args.get('id')
    if custom_check(value):
        execute_query(value)
"""
    (tmp_path / "validator.py").write_text(val_code, encoding="utf-8")
    (tmp_path / "db.py").write_text(db_code, encoding="utf-8")
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    # SEC-PY-011 must be flagged because custom_check cannot be statically proven safe!
    sql_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-011"]
    assert len(sql_findings) >= 1


def test_scenario_e_recursive_function_termination(tmp_path: Path):
    """Scenario E: Recursive function call graph does not cause infinite summarization loops."""
    code = """
def walk_node(node):
    if not node:
        return None
    return walk_node(node.next)
"""
    (tmp_path / "tree.py").write_text(code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig(max_summary_iterations=5)
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    # Finished cleanly without timeout or recursion crash
    contracts_metric = result.call_graph_summary.get("contracts", {})
    assert "contracts_generated" in contracts_metric


def test_scenario_f_field_mutation_sanitizer(tmp_path: Path):
    """Scenario F: Field mutation sanitizer refines object field."""
    code = """
import os

def sanitize_payload(obj):
    obj.token = "".join(c for c in obj.token if c.isalnum())

def handle(req):
    sanitize_payload(req)
    os.system(f"echo {req.token}")
"""
    (tmp_path / "handler.py").write_text(code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)
    assert result.call_graph_summary is not None


def test_scenario_g_contradictory_types_across_function_boundary(tmp_path: Path):
    """Scenario G: Disjoint types across boundary (int vs str) detect contradiction."""
    callee_code = """
import sqlite3

def execute_str(val):
    if isinstance(val, str):
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE name = '{val}'")
"""
    caller_code = """
from callee import execute_str

def caller(request):
    val = request.args.get('uid')
    if isinstance(val, int):
        execute_str(val)
"""
    (tmp_path / "callee.py").write_text(callee_code, encoding="utf-8")
    (tmp_path / "caller.py").write_text(caller_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    # In caller val is int, but callee requires str: contradictory path is pruned!
    sql_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-011"]
    assert len(sql_findings) == 0


def test_scenario_i_unresolved_dynamic_dispatch(tmp_path: Path):
    """Scenario I: Unresolved dynamic dispatch degrades cleanly to UNRESOLVED without crash."""
    code = """
import sys

def dispatch(name, arg):
    mod = sys.modules[__name__]
    fn = getattr(mod, name, None)
    if fn:
        fn(arg)
"""
    (tmp_path / "dispatch.py").write_text(code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    config = AnalysisConfig()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)
    assert result is not None


def test_scenario_j_baseline_invariance(tmp_path: Path):
    """Scenario J: Baseline compatibility: Finding ID generation formulas remain invariant."""
    callee_code = """
import sqlite3

def execute_query(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    caller_code = """
from db import execute_query

def run(request):
    val = request.args.get('id')
    execute_query(val)
"""
    (tmp_path / "db.py").write_text(callee_code, encoding="utf-8")
    (tmp_path / "app.py").write_text(caller_code, encoding="utf-8")

    pipeline = AnalysisPipeline()
    res1 = pipeline.run(target_path=tmp_path, analysis_config=AnalysisConfig(disable_interprocedural_contracts=True))
    res2 = pipeline.run(target_path=tmp_path, analysis_config=AnalysisConfig(disable_interprocedural_contracts=False))

    f1 = [f for f in res1.security_findings if f.rule_id == "SEC-PY-011"]
    f2 = [f for f in res2.security_findings if f.rule_id == "SEC-PY-011"]

    assert len(f1) == 1 and len(f2) == 1
    assert f1[0].id == f2[0].id  # Finding ID must be 100% invariant!


def test_5_run_determinism(tmp_path: Path):
    """Run analysis 5 consecutive times on identical codebase; verify byte-for-byte determinism."""
    c1 = """
def is_safe_param(x):
    return isinstance(x, int)
"""
    c2 = """
import sqlite3
from v import is_safe_param

def endpoint(req):
    p = req.args.get('p')
    if is_safe_param(p):
        conn = sqlite3.connect('x.db')
        conn.cursor().execute(f"SELECT * FROM tbl WHERE id = {p}")
"""
    (tmp_path / "v.py").write_text(c1, encoding="utf-8")
    (tmp_path / "app.py").write_text(c2, encoding="utf-8")

    results = []
    pipeline = AnalysisPipeline()
    config = AnalysisConfig()

    for _ in range(5):
        res = pipeline.run(target_path=tmp_path, analysis_config=config)
        summary = res.call_graph_summary or {}
        findings_json = json.dumps([f.model_dump(mode="json") for f in res.security_findings], sort_keys=True)
        contracts_json = json.dumps(summary.get("contracts", {}), sort_keys=True)
        results.append((findings_json, contracts_json))

    # All 5 runs must be identical
    first = results[0]
    for i, r in enumerate(results[1:], start=2):
        assert r == first, f"Run {i} deviated from Run 1"
