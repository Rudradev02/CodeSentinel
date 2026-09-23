"""Tests for Phase 14 multi-target reporters: Markdown, HTML, JUnit, GitLab."""

import json
import xml.etree.ElementTree as ET
import pytest

from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.comparison.diff import BaselineComparator
from analyzer.models.comparison import ComparisonResult
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisResult, RepositoryInfo
from analyzer.reporting.gitlab_reporter import GitlabReporter
from analyzer.reporting.html_reporter import HtmlReporter
from analyzer.reporting.junit_reporter import JunitReporter
from analyzer.reporting.markdown_reporter import MarkdownReporter


@pytest.fixture
def sample_analysis_result() -> AnalysisResult:
    """Run pipeline against fixture to obtain a realistic AnalysisResult."""
    pipeline = AnalysisPipeline()
    return pipeline.run("analyzer/tests/fixtures/sample_project")


def test_markdown_reporter_render_scan(sample_analysis_result: AnalysisResult):
    """MarkdownReporter renders complete PR review markdown with badges, summary, and findings."""
    reporter = MarkdownReporter()
    output = reporter.render(sample_analysis_result)

    assert "# 🛡️ CodeSentinel Static Analysis Report" in output
    assert "Overall Health" in output
    assert "Scan Summary" in output
    assert "| Severity | Count | Category | Count |" in output
    assert "| Sev | Rule | Location | Description |" in output
    assert "Generated deterministically by CodeSentinel" in output


def test_markdown_reporter_render_comparison(sample_analysis_result: AnalysisResult):
    """MarkdownReporter renders differential baseline comparison with regressions and resolved items."""
    comparison = BaselineComparator.compare(current=sample_analysis_result, baseline=sample_analysis_result)
    reporter = MarkdownReporter()
    output = reporter.render_comparison(comparison)

    assert "CodeSentinel Differential Regression Report" in output
    assert "Health Impact" in output
    assert "New Regressions" in output


def test_html_reporter_standalone_and_no_cdns(sample_analysis_result: AnalysisResult):
    """HtmlReporter generates fully self-contained HTML with zero external CDN references."""
    reporter = HtmlReporter()
    html_output = reporter.render(sample_analysis_result)

    assert "<!DOCTYPE html>" in html_output
    assert "<html lang=\"en\">" in html_output
    assert "<style>" in html_output
    assert "<script>" in html_output

    # Zero external CDN links
    lower_html = html_output.lower()
    assert "https://cdn." not in lower_html
    assert "http://cdn." not in lower_html
    assert "cdnjs.cloudflare.com" not in lower_html
    assert "unpkg.com" not in lower_html
    assert "jsdelivr.net" not in lower_html


def test_html_reporter_xss_escaping():
    """HtmlReporter strictly escapes HTML tags and scripts in messages and snippets."""
    malicious_finding = Finding(
        rule_id="SEC-PY-001",
        rule_name="Hardcoded API Secret",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        evidence_type=EvidenceType.DETERMINISTIC,
        message="Vulnerable <script>alert('pwned')</script>",
        description="Explanation with <img src=x onerror=alert(1)>",
        remediation="Sanitize <b>input</b>",
        location=SourceLocation(file_path="app/<test>.py", line_start=10),
        code_snippet="password = '<script>evil()</script>'",
    )
    result = AnalysisResult(
        target_path="/test",
        repository=RepositoryInfo(name="test", path="/test", local_path="/test"),
        security_findings=[malicious_finding],
    )

    reporter = HtmlReporter()
    output = reporter.render(result)

    assert "<script>alert('pwned')</script>" not in output
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in output
    assert "<img src=x onerror=alert(1)>" not in output


def test_junit_reporter_valid_xml(sample_analysis_result: AnalysisResult):
    """JunitReporter produces well-formed XML parseable by standard ElementTree."""
    reporter = JunitReporter()
    xml_output = reporter.render(sample_analysis_result)

    root = ET.fromstring(xml_output)
    assert root.tag == "testsuites"
    assert "name" in root.attrib
    assert root.attrib["name"] == "CodeSentinel"

    suite = root.find("testsuite")
    assert suite is not None
    assert "tests" in suite.attrib
    assert "failures" in suite.attrib

    testcases = suite.findall("testcase")
    assert len(testcases) >= 1
    for tc in testcases:
        assert "classname" in tc.attrib
        assert "name" in tc.attrib
        assert "file" in tc.attrib
        assert "line" in tc.attrib


def test_gitlab_reporter_schema(sample_analysis_result: AnalysisResult):
    """GitlabReporter produces valid JSON array conforming to GitLab Code Quality schema."""
    reporter = GitlabReporter()
    json_output = reporter.render(sample_analysis_result)

    items = json.loads(json_output)
    assert isinstance(items, list)
    assert len(items) == len(sample_analysis_result.security_findings) + len(sample_analysis_result.architecture_findings)

    for item in items:
        assert "description" in item
        assert "check_name" in item
        assert "fingerprint" in item
        assert len(item["fingerprint"]) in (32, 36)
        assert "severity" in item
        assert item["severity"] in ["critical", "major", "minor", "info"]
        assert "location" in item
        assert "path" in item["location"]
        assert "lines" in item["location"]
        assert "begin" in item["location"]["lines"]
