"""Unit tests for Phase 16 Reporting and SARIF schema enrichment."""

import json
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisMetadata, AnalysisResult, RepositoryInfo
from analyzer.reporting.markdown_reporter import MarkdownReporter
from analyzer.reporting.sarif import SarifReporter
from analyzer.reporting.terminal import TerminalReporter


def _create_sample_phase16_result():
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
    }
    finding = Finding(
        id="finding-sarif-1",
        rule_id="SEC-PY-011",
        rule_name="Cross-Function SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="repo.find_by_id(uid)",
        description="SQL injection reaches sink in UserRepository",
        remediation="Use parameterized queries",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "path_summary": "request.args['id'] -> UserRepository.find_by_id() -> execute()",
            "call_chain": [step],
            "source": {"expression": "request.args['id']", "file_path": "app/views.py", "line": 24},
            "sink": {"callee": "execute", "file_path": "app/repo.py", "line": 50},
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
            "type_resolution": {
                "types_inferred": 8,
                "type_aware_edges": 12,
                "ambiguous_receivers": 0,
                "confidence_distribution": {"KNOWN": 12},
            },
            "context_sensitivity": {
                "total_contexts": 5,
                "max_depth_reached": 2,
                "contexts_truncated": 0,
                "truncation_reasons": [],
            },
        },
    )


def test_sarif_reporter_phase16_properties():
    result = _create_sample_phase16_result()
    sarif_reporter = SarifReporter()
    sarif_output = sarif_reporter.render(result)
    sarif_json = json.loads(sarif_output)

    assert sarif_json["version"] == "2.1.0"
    results = sarif_json["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]
    assert "codeFlows" in res
    tfl = res["codeFlows"][0]["threadFlows"][0]["locations"]
    # Look for the call chain step location
    step_loc = next((loc for loc in tfl if "Receiver: KNOWN" in loc["message"]["text"]), None)
    assert step_loc is not None
    assert "properties" in step_loc
    assert step_loc["properties"]["typeConfidence"] == "KNOWN"
    assert step_loc["properties"]["receiverType"] == "app.repo.UserRepository"
    assert step_loc["properties"]["contextId"] == "ctx-a1b2c3"


def test_terminal_reporter_phase16_output():
    result = _create_sample_phase16_result()
    reporter = TerminalReporter()
    text = reporter.render(result)

    assert "TYPE & CONTEXT PRECISION (PHASE 16)" in text
    assert "Types Inferred      : 8" in text
    assert "Type-Aware Edges    : 12" in text
    assert "Active Contexts     : 5" in text
    assert "Receiver: app.repo.UserRepository (KNOWN)" in text
    assert "Context: ctx-a1b2c3" in text


def test_markdown_reporter_phase16_output():
    result = _create_sample_phase16_result()
    reporter = MarkdownReporter()
    md = reporter.render(result)

    assert "Cross-Function Taint" in md
    assert "Receiver: `app.repo.UserRepository` (KNOWN)" in md
    assert "Context: `ctx-a1b2c3`" in md
