"""Unit tests for Phase 17 Reporting and SARIF schema enrichment."""

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


def _create_sample_phase17_result():
    loc = SourceLocation(file_path="app/views.py", line_start=25, col_start=4)
    step = {
        "caller_function": "handle_request",
        "callee_function": "UserRepository.find_by_id",
        "caller_file": "app/views.py",
        "callee_file": "app/repo.py",
        "call_site_line": 26,
        "call_site_col": 8,
        "argument_index": 0,
        "callee_param_name": "user_id",
        "taint_action": "REACHES_SINK",
        "receiver_type": "app.repo.UserRepository",
        "receiver_confidence": "KNOWN",
        "context_id": "ctx-a1b2c3",
        "alias_path": "alias_repo -> repo",
        "field_path": "req.payload",
        "allocation_site": "ALLOC:app/views.py:25:4:UserRepository:handle_request",
    }
    finding = Finding(
        id="finding-sarif-alias-1",
        rule_id="SEC-PY-011",
        rule_name="Cross-Function SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="alias_repo.find_by_id(uid)",
        description="SQL injection reaches sink through aliased receiver",
        remediation="Use parameterized queries",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "path_summary": "request.args['id'] -> UserRepository.find_by_id() -> execute()",
            "call_chain": [step],
            "source": {"expression": "request.args['id']", "file_path": "app/views.py", "line": 24},
            "sink": {"callee": "execute", "file_path": "app/repo.py", "line": 50},
            "alias_evidence": [{"step": "step_0", "alias_path": "alias_repo -> repo"}],
            "field_evidence": [{"step": "step_0", "field_path": "req.payload"}],
        },
    )
    repo = RepositoryInfo(name="test-repo", local_path=".")
    return AnalysisResult(
        repository=repo,
        security_findings=[finding],
        call_graph_summary={
            "total_functions": 10,
            "total_call_edges": 15,
            "resolved_local": 10,
            "resolved_import": 5,
            "unresolved": 0,
            "resolution_rate": 1.0,
            "summarized_functions": 10,
            "unsummarized_functions": 0,
            "interprocedural_findings_count": 1,
            "max_call_depth_reached": 2,
            "alias_analysis": {
                "abstract_objects_count": 14,
                "alias_bindings_count": 8,
                "field_edges_count": 6,
                "ambiguous_points_to_count": 1,
                "truncated_points_to_count": 0,
            },
        },
    )


def test_sarif_reporter_phase17_properties():
    result = _create_sample_phase17_result()
    sarif_reporter = SarifReporter()
    sarif_output = sarif_reporter.render(result)
    sarif_json = json.loads(sarif_output)

    assert sarif_json["version"] == "2.1.0"
    results = sarif_json["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]
    assert "codeFlows" in res
    tfl = res["codeFlows"][0]["threadFlows"][0]["locations"]
    
    # Check thread flow location contains alias, field, and alloc properties
    step_loc = next((loc for loc in tfl if "alias_repo -> repo" in loc.get("properties", {}).get("aliasPath", "")), None)
    assert step_loc is not None
    assert step_loc["properties"]["aliasPath"] == "alias_repo -> repo"
    assert step_loc["properties"]["fieldPath"] == "req.payload"
    assert "ALLOC:" in step_loc["properties"]["allocationSite"]


def test_terminal_reporter_phase17_output():
    result = _create_sample_phase17_result()
    reporter = TerminalReporter()
    text = reporter.render(result)

    assert "Alias & Points-To: 14 objects | 8 bindings | 6 fields | 1 ambiguous | 0 widened" in text
    assert "Alias: alias_repo -> repo" in text
    assert "Field: req.payload" in text


def test_markdown_reporter_phase17_output():
    result = _create_sample_phase17_result()
    reporter = MarkdownReporter()
    md = reporter.render(result)

    assert "Alias: `alias_repo -> repo`" in md
    assert "Field: `req.payload`" in md
