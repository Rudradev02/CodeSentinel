"""Unit tests for Phase 19 Reporting and SARIF schema enrichment."""

import json
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisResult, RepositoryInfo
from analyzer.reporting.markdown_reporter import MarkdownReporter
from analyzer.reporting.sarif import SarifReporter
from analyzer.reporting.terminal import TerminalReporter


def _create_sample_phase19_result():
    loc = SourceLocation(file_path="app/controllers.py", line_start=30, col_start=4)
    step = {
        "caller_function": "handle_user_input",
        "callee_function": "UserValidator.validate_id",
        "caller_file": "app/controllers.py",
        "callee_file": "app/validators.py",
        "call_site_line": 32,
        "call_site_col": 8,
        "argument_index": 0,
        "callee_param_name": "user_id",
        "taint_action": "TRANSFERS_TAINT",
        "context_id": "ctx-contract-1",
        "contract_status": "SATISFIED",
        "contract_effect": "EFFECT:CLEARS_TAINT:html_escape",
        "precondition_kind": "TYPE_REFINEMENT",
        "contract_id": "urn:codesentinel:contract:app.validators:validate_id:ROOT",
        "path_condition": "validate_id(user_id) == True",
        "branch_taken": "TRUE_BRANCH",
        "path_status": "FEASIBLE",
    }
    finding = Finding(
        id="finding-sarif-contract-1",
        rule_id="SEC-PY-011",
        rule_name="Cross-Function SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="execute_query(user_id)",
        description="SQL injection reaches sink with governing interprocedural contract",
        remediation="Ensure input validation satisfies contract",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "path_summary": "request.args['id'] -> UserValidator.validate_id() -> execute()",
            "call_chain": [step],
            "source": {"expression": "request.args['id']", "file_path": "app/controllers.py", "line": 31},
            "sink": {"callee": "execute", "file_path": "app/db.py", "line": 65},
        },
    )
    repo = RepositoryInfo(name="test-contract-repo", local_path=".")
    return AnalysisResult(
        repository=repo,
        security_findings=[finding],
        architecture_findings=[],
        call_graph_summary={
            "total_functions": 15,
            "total_call_edges": 20,
            "contracts": {
                "contracts_generated": 12,
                "preconditions_verified": 8,
                "postconditions_propagated": 5,
                "multi_hop_guards_resolved": 3,
                "contracts_widened": 1,
                "recursive_sccs_resolved": 2,
            },
        },
    )


def test_terminal_reporter_contracts():
    """Verify terminal reporter output includes Phase 19 contract metrics and trace steps."""
    result = _create_sample_phase19_result()
    reporter = TerminalReporter()
    output = reporter.render(result)

    assert "Contracts & Summaries: 12 generated" in output
    assert "8 preconditions" in output
    assert "INTERPROCEDURAL CONTRACTS (PHASE 19):" in output
    assert "Contracts Generated      : 12" in output
    assert "Preconditions Verified   : 8" in output
    assert "Postconditions Propagated: 5" in output
    assert "Multi-Hop Guards Resolved: 3" in output
    assert "Contract: SATISFIED" in output
    assert "Effect: EFFECT:CLEARS_TAINT:html_escape" in output


def test_markdown_reporter_contracts():
    """Verify markdown reporter renders contract metrics and call chain badges."""
    result = _create_sample_phase19_result()
    reporter = MarkdownReporter()
    output = reporter.render(result)

    assert "### Interprocedural Contracts (Phase 19)" in output
    assert "Contracts Generated | 12" in output
    assert "Preconditions Verified | 8" in output
    assert "Contract: `SATISFIED`" in output
    assert "Effect: `EFFECT:CLEARS_TAINT:html_escape`" in output


def test_sarif_reporter_contracts():
    """Verify SARIF v2.1.0 output serializes contract properties cleanly."""
    result = _create_sample_phase19_result()
    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    code_flows = results[0]["codeFlows"]
    assert len(code_flows) == 1
    locations = code_flows[0]["threadFlows"][0]["locations"]
    assert len(locations) == 3

    step_loc = locations[1]
    props = step_loc.get("properties", {})
    assert props.get("contractStatus") == "SATISFIED"
    assert props.get("contractEffect") == "EFFECT:CLEARS_TAINT:html_escape"
    assert props.get("preconditionKind") == "TYPE_REFINEMENT"
    assert props.get("contractId") == "urn:codesentinel:contract:app.validators:validate_id:ROOT"
