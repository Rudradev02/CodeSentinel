"""Tests for Phase 15 Workstream 15.7: Interprocedural Security Rules."""

from analyzer.dataflow.callgraph.models import CallChainStep, InterproceduralTaintPath
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.findings import FindingConfidence, FindingSeverity
from analyzer.security.javascript.sec_js_009_dom_xss_interprocedural import RuleSecJs009
from analyzer.security.javascript.sec_js_010_eval_interprocedural import RuleSecJs010
from analyzer.security.python.sec_py_011_sql_interprocedural import RuleSecPy011
from analyzer.security.python.sec_py_012_subprocess_interprocedural import RuleSecPy012


def test_sec_py_011_sql_interprocedural():
    """Verify SEC-PY-011 generates expected Finding from InterproceduralTaintPath."""
    rule = RuleSecPy011()
    assert rule.rule_id == "SEC-PY-011"
    assert rule.severity == FindingSeverity.HIGH
    assert rule.cwe_id == "CWE-89"

    step = CallChainStep(
        caller_function="views.handle_request",
        callee_function="utils.db.build_query",
        caller_file="views.py",
        callee_file="utils/db.py",
        call_site_line=13,
        call_site_col=4,
        argument_index=0,
        callee_param_name="user_input",
        taint_action="PROPAGATE_THROUGH",
    )
    path = InterproceduralTaintPath(
        flow_type="INTER_PROCEDURAL_TAINT",
        source={"source_id": "REQUEST_ARGS", "file_path": "views.py", "line": 12, "column": 4},
        call_chain=[step],
        sink={"sink_id": "SQL_EXECUTE", "file_path": "views.py", "line": 14, "column": 4, "expression": "cursor.execute(query)"},
        path_summary="request.args -> build_query() -> cursor.execute",
        category=SinkCategory.SQL_EXECUTE,
        total_depth=1,
        files_involved=["views.py", "utils/db.py"],
    )

    code = "def handle_request():\n    user_id = request.args['id']\n    query = build_query(user_id)\n    cursor.execute(query)\n"
    findings = rule.analyze(
        file_path="views.py",
        content=code,
        interprocedural_paths=[path],
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-PY-011"
    assert f.severity == FindingSeverity.HIGH
    assert f.location.file_path == "views.py"
    assert f.location.line_start == 14
    assert f.evidence["flow_type"] == "INTER_PROCEDURAL_TAINT"
    assert len(f.evidence["call_chain"]) == 1
    assert f.evidence["call_chain"][0]["callee_function"] == "utils.db.build_query"


def test_sec_py_012_subprocess_interprocedural():
    """Verify SEC-PY-012 generates expected Finding for cross-function command injection."""
    rule = RuleSecPy012()
    assert rule.rule_id == "SEC-PY-012"
    assert rule.severity == FindingSeverity.CRITICAL
    assert rule.cwe_id == "CWE-78"

    step = CallChainStep(
        caller_function="handler.process",
        callee_function="runner.exec_cmd",
        caller_file="handler.py",
        callee_file="runner.py",
        call_site_line=10,
        call_site_col=4,
        argument_index=0,
        callee_param_name="cmd",
        taint_action="REACHES_SINK",
    )
    path = InterproceduralTaintPath(
        flow_type="INTER_PROCEDURAL_TAINT",
        source={"source_id": "REQUEST_FORM", "file_path": "handler.py", "line": 5, "column": 4},
        call_chain=[step],
        sink={"sink_id": "SUBPROCESS_RUN", "file_path": "runner.py", "line": 20, "column": 4, "expression": "subprocess.run(cmd, shell=True)"},
        path_summary="request.form -> exec_cmd() -> subprocess.run",
        category=SinkCategory.COMMAND_EXECUTE,
        total_depth=1,
        files_involved=["handler.py", "runner.py"],
    )

    findings = rule.analyze(
        file_path="runner.py",
        content="def exec_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n",
        interprocedural_paths=[path],
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-PY-012"
    assert f.severity == FindingSeverity.CRITICAL
    assert f.location.file_path == "runner.py"
    assert f.location.line_start == 20


def test_sec_js_009_dom_xss_interprocedural():
    """Verify SEC-JS-009 generates expected Finding for cross-function DOM XSS."""
    rule = RuleSecJs009()
    assert rule.rule_id == "SEC-JS-009"
    assert rule.severity == FindingSeverity.HIGH
    assert rule.cwe_id == "CWE-79"

    step = CallChainStep(
        caller_function="app.renderUser",
        callee_function="card.createCard",
        caller_file="app.js",
        callee_file="card.js",
        call_site_line=8,
        call_site_col=2,
        argument_index=0,
        callee_param_name="name",
        taint_action="PROPAGATE_THROUGH",
    )
    path = InterproceduralTaintPath(
        flow_type="INTER_PROCEDURAL_TAINT",
        source={"source_id": "LOCATION_SEARCH", "file_path": "app.js", "line": 7, "column": 2},
        call_chain=[step],
        sink={"sink_id": "DOM_INNERHTML", "file_path": "app.js", "line": 9, "column": 2, "expression": "element.innerHTML = card"},
        path_summary="location.search -> createCard() -> element.innerHTML",
        category=SinkCategory.DOM_INJECTION,
        total_depth=1,
        files_involved=["app.js", "card.js"],
    )

    findings = rule.analyze(
        file_path="app.js",
        content="const card = createCard(name);\nelement.innerHTML = card;\n",
        interprocedural_paths=[path],
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-JS-009"
    assert f.severity == FindingSeverity.HIGH
    assert f.location.file_path == "app.js"


def test_sec_js_010_eval_interprocedural():
    """Verify SEC-JS-010 generates expected Finding for cross-function code evaluation."""
    rule = RuleSecJs010()
    assert rule.rule_id == "SEC-JS-010"
    assert rule.severity == FindingSeverity.CRITICAL
    assert rule.cwe_id == "CWE-95"

    step = CallChainStep(
        caller_function="worker.handleTask",
        callee_function="executor.runCode",
        caller_file="worker.js",
        callee_file="executor.js",
        call_site_line=15,
        call_site_col=2,
        argument_index=0,
        callee_param_name="code",
        taint_action="REACHES_SINK",
    )
    path = InterproceduralTaintPath(
        flow_type="INTER_PROCEDURAL_TAINT",
        source={"source_id": "MESSAGE_DATA", "file_path": "worker.js", "line": 12, "column": 2},
        call_chain=[step],
        sink={"sink_id": "JS_EVAL", "file_path": "executor.js", "line": 5, "column": 2, "expression": "eval(code)"},
        path_summary="message.data -> runCode() -> eval()",
        category=SinkCategory.CODE_EVAL,
        total_depth=1,
        files_involved=["worker.js", "executor.js"],
    )

    findings = rule.analyze(
        file_path="executor.js",
        content="function runCode(code) {\n  eval(code);\n}\n",
        interprocedural_paths=[path],
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-JS-010"
    assert f.severity == FindingSeverity.CRITICAL
    assert f.location.file_path == "executor.js"


def test_finding_id_determinism():
    """Verify identical paths produce identical UUIDv5 finding IDs."""
    rule = RuleSecPy011()
    step = CallChainStep(
        caller_function="a.b",
        callee_function="c.d",
        caller_file="a.py",
        callee_file="c.py",
        call_site_line=10,
        call_site_col=0,
        argument_index=0,
        callee_param_name="x",
        taint_action="PROPAGATE_THROUGH",
    )
    path1 = InterproceduralTaintPath(
        source={"file_path": "a.py", "line": 5},
        call_chain=[step],
        sink={"file_path": "a.py", "line": 15},
        path_summary="a -> c -> a",
        category=SinkCategory.SQL_EXECUTE,
    )
    path2 = InterproceduralTaintPath(
        source={"file_path": "a.py", "line": 5},
        call_chain=[step],
        sink={"file_path": "a.py", "line": 15},
        path_summary="a -> c -> a",
        category=SinkCategory.SQL_EXECUTE,
    )

    f1 = rule.create_finding_from_path(path1)
    f2 = rule.create_finding_from_path(path2)
    assert f1.id == f2.id
