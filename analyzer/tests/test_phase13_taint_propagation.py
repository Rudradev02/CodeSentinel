"""Unit and E2E scenario tests for Phase 13 taint propagation and security rules."""

import ast
import pytest

from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.security.python.sec_py_009_sql_dataflow import RuleSecPy009
from analyzer.security.python.sec_py_010_subprocess_dataflow import RuleSecPy010
from analyzer.security.javascript.sec_js_007_dom_xss_dataflow import RuleSecJs007
from analyzer.security.javascript.sec_js_008_eval_dataflow import RuleSecJs008


def test_scenario_1_direct_sql_taint():
    """Scenario 1: Direct SQL injection via variable propagation."""
    code = """
def get_user():
    user_id = request.args["id"]
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
"""
    rule = RuleSecPy009()
    findings = rule.analyze("views.py", code)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-PY-009"
    assert f.location.line_start == 5
    assert f.evidence["flow_type"] == "INTRA_PROCEDURAL_TAINT"
    assert f.evidence["sink"]["tainted_argument"] == "query"
    assert "request.args['id']" in f.evidence["path_summary"]


def test_scenario_2_parameterized_sql_safe():
    """Scenario 2: Parameterized query with untrusted input in parameters is SAFE."""
    code = """
def get_user():
    user_id = request.args["id"]
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )
"""
    rule = RuleSecPy009()
    findings = rule.analyze("views.py", code)
    # Safe sink usage: parameter binding handles query safely
    assert len(findings) == 0


def test_scenario_3_numeric_constraint():
    """Scenario 3: Numeric constraint int() neutralizes SQL injection in numeric context."""
    code = """
def get_user_numeric():
    user_id = int(request.args["id"])
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
"""
    rule = RuleSecPy009()
    findings = rule.analyze("views.py", code)
    assert len(findings) == 0


def test_scenario_4_unknown_transformation():
    """Scenario 4: Unknown custom function does NOT clear taint."""
    code = """
def process():
    value = request.args["id"]
    value = custom_normalize(value)
    cursor.execute(value)
"""
    rule = RuleSecPy009()
    findings = rule.analyze("views.py", code)
    assert len(findings) == 1
    assert "UNKNOWN_TRANSFORMATION" in [s["operation"] for s in findings[0].evidence["propagation"]]


def test_scenario_5_shadowing_prevents_leak():
    """Scenario 5: Inner scope variable shadowing must not inherit outer taint."""
    code = """
def outer():
    value = request.args["id"]

def safe_function():
    value = "safe"
    cursor.execute(value)
"""
    rule = RuleSecPy009()
    findings = rule.analyze("views.py", code)
    # safe_function() defines value = "safe", so no finding inside safe_function
    assert len(findings) == 0


def test_command_injection_rule_sec_py_010():
    """Verify SEC-PY-010 command injection detection and shlex.quote sanitization."""
    vulnerable_code = """
def run_command():
    cmd = request.args["cmd"]
    full_cmd = "echo " + cmd
    subprocess.run(full_cmd)
"""
    rule = RuleSecPy010()
    vuln_findings = rule.analyze("tasks.py", vulnerable_code)
    assert len(vuln_findings) == 1
    assert vuln_findings[0].rule_id == "SEC-PY-010"

    safe_code = """
def run_safe():
    cmd = shlex.quote(request.args["cmd"])
    full_cmd = "echo " + cmd
    subprocess.run(full_cmd)
"""
    safe_findings = rule.analyze("tasks.py", safe_code)
    assert len(safe_findings) == 0


def test_dom_xss_rule_sec_js_007():
    """Verify SEC-JS-007 DOM XSS detection and DOMPurify sanitization."""
    vuln_js = """
function renderProfile() {
    const raw = location.search;
    const markup = "<div>" + raw + "</div>";
    document.write(markup);
}
"""
    rule = RuleSecJs007()
    findings = rule.analyze("profile.js", vuln_js)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-007"

    safe_js = """
function renderSafe() {
    const raw = location.search;
    const clean = DOMPurify.sanitize(raw);
    document.write(clean);
}
"""
    safe_findings = rule.analyze("profile.js", safe_js)
    assert len(safe_findings) == 0


def test_dynamic_eval_rule_sec_js_008():
    """Verify SEC-JS-008 dynamic eval detection."""
    vuln_js = """
function executeDynamic() {
    const code = req.query;
    eval(code);
}
"""
    rule = RuleSecJs008()
    findings = rule.analyze("handler.js", vuln_js)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-008"
