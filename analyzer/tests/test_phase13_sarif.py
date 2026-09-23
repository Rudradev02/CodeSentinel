"""Tests verifying OASIS SARIF v2.1.0 codeFlows generation for Phase 13 findings."""

import json
from pathlib import Path
import pytest

from analyzer.models.results import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisStatus,
    ArchitectureSummary,
    RepositoryInfo,
    SecuritySummary,
)
from analyzer.models.graph import ArchitectureGraph
from analyzer.reporting.sarif import SarifReporter
from analyzer.security.python.sec_py_009_sql_dataflow import RuleSecPy009


def test_sarif_codeflows_for_taint_finding():
    """Verify that SARIF output embeds codeFlows and threadFlows for data-flow findings."""
    code = """
def query_user():
    uid = request.args["id"]
    sql = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(sql)
"""
    rule = RuleSecPy009()
    findings = rule.analyze("api/users.py", code)
    assert len(findings) == 1

    result = AnalysisResult(
        metadata=AnalysisMetadata(
            schema_version="1.0.0",
            status=AnalysisStatus.COMPLETED,
            duration_seconds=0.1,
            analyzer_version="0.1.0",
        ),
        repository=RepositoryInfo(
            name="test_repo",
            local_path=str(Path(".").resolve()),
            languages={"PYTHON": 100.0},
        ),
        security_findings=findings,
        architecture_findings=[],
        graph=ArchitectureGraph(),
        security_summary=SecuritySummary(total=1, high=1),
        architecture_summary=ArchitectureSummary(total_modules=1),
    )

    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    sarif_doc = json.loads(sarif_str)

    assert sarif_doc["version"] == "2.1.0"
    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 1

    r = results[0]
    assert r["ruleId"] == "SEC-PY-009"
    assert "codeFlows" in r
    assert len(r["codeFlows"]) == 1
    thread_flows = r["codeFlows"][0]["threadFlows"]
    assert len(thread_flows) == 1

    locations = thread_flows[0]["locations"]
    assert len(locations) >= 3  # Source, propagation, sink
    assert "Source:" in locations[0]["message"]["text"]
    assert "Sink:" in locations[-1]["message"]["text"]
