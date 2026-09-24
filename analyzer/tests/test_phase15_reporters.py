"""Tests for Phase 15 reporting extensions across Terminal, Markdown, HTML, and JUnit reporters."""

import json
from pathlib import Path

from analyzer.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
    EvidenceType,
)
from analyzer.models.results import AnalysisMetadata, AnalysisResult, AnalysisStatus, RepositoryInfo
from analyzer.reporting.terminal import TerminalReporter
from analyzer.reporting.markdown_reporter import MarkdownReporter
from analyzer.reporting.html_reporter import HtmlReporter
from analyzer.reporting.junit_reporter import JunitReporter


def _create_sample_interprocedural_result():
    cg_summary = {
        "total_functions": 12,
        "total_call_edges": 18,
        "resolved_local": 14,
        "resolved_import": 4,
        "unresolved": 0,
        "resolution_rate": 1.0,
        "summarized_functions": 12,
        "unsummarized_functions": 0,
        "interprocedural_findings_count": 1,
        "max_call_depth_reached": 2,
    }

    finding = Finding(
        id="f15-test-uuid",
        rule_id="SEC-PY-011",
        rule_name="Interprocedural SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        message="Cross-function SQL injection detected",
        description="User input flows from handler to query helper and sinks into execute()",
        remediation="Use parameterized queries",
        location=SourceLocation(file_path="views.py", line_start=20, line_end=20),
        code_snippet="cursor.execute(query)",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "source": {
                "expression": "request.args.get('id')",
                "file_path": "views.py",
                "line": 10,
                "column": 4,
            },
            "call_chain": [
                {
                    "caller_function": "handle_request",
                    "callee_function": "build_query",
                    "caller_file": "views.py",
                    "callee_file": "utils/query.py",
                    "call_site_line": 15,
                    "call_site_col": 12,
                    "argument_index": 0,
                    "callee_param_name": "user_id",
                    "taint_action": "ARG_TO_RETURN",
                }
            ],
            "sink": {
                "callee": "cursor.execute",
                "file_path": "views.py",
                "line": 20,
                "column": 4,
            },
            "path_summary": "request.args.get('id') -> build_query() -> cursor.execute()",
            "total_depth": 1,
            "files_involved": ["views.py", "utils/query.py"],
        },
    )

    return AnalysisResult(
        id="res-15-test",
        status=AnalysisStatus.COMPLETED,
        repository=RepositoryInfo(name="phase15_repo", local_path="/test/repo"),
        metadata=AnalysisMetadata(duration_seconds=1.23),
        security_findings=[finding],
        architecture_findings=[],
        call_graph_summary=cg_summary,
    )


def test_terminal_reporter_phase15():
    res = _create_sample_interprocedural_result()
    reporter = TerminalReporter()
    text = reporter.render(res)

    assert "CALL GRAPH INTELLIGENCE:" in text
    assert "Functions: 12" in text
    assert "Resolution Rate: 100.0%" in text
    assert "Interprocedural Taint Flow:" in text
    assert "handle_request() -> build_query() at views.py:15" in text
    assert "utils/query.py" in text


def test_markdown_reporter_phase15():
    res = _create_sample_interprocedural_result()
    reporter = MarkdownReporter()
    md = reporter.render(res)

    assert "### 🧬 Data-Flow & Taint Traces" in md
    assert "[Cross-Function Taint]" in md
    assert "**Call Chain Steps**:" in md
    assert "`handle_request()` → `build_query()` at `views.py:15`" in md


def test_html_reporter_phase15():
    res = _create_sample_interprocedural_result()
    reporter = HtmlReporter()
    html = reporter.render(res)

    assert "View Cross-Function Taint Trace" in html
    assert "<code>handle_request()</code> &rarr; <code>build_query()</code>" in html
    assert "views.py:15" in html


def test_junit_reporter_phase15():
    res = _create_sample_interprocedural_result()
    reporter = JunitReporter(failure_threshold=FindingSeverity.HIGH)
    xml = reporter.render(res)

    assert 'failures="1"' in xml
    assert "Taint Path:" in xml
    assert "Call Chain:" in xml
    assert "handle_request() -&gt; build_query() at views.py:15" in xml
