"""Tests for Phase 15 SARIF multi-file codeFlows generation."""

import json
from analyzer.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
    EvidenceType,
)
from analyzer.models.results import AnalysisMetadata, AnalysisResult, AnalysisStatus, RepositoryInfo
from analyzer.reporting.sarif import SarifReporter


def test_sarif_interprocedural_multifile_codeflows():
    """Verify that INTER_PROCEDURAL_TAINT finding produces multi-file codeFlows and artifacts."""
    finding = Finding(
        id="sarif-p15-finding",
        rule_id="SEC-PY-011",
        rule_name="Interprocedural SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        message="Cross-function SQL injection",
        description="Tainted flow across files",
        remediation="Parameterized queries",
        location=SourceLocation(file_path="views/handlers.py", line_start=25, line_end=25),
        code_snippet="cursor.execute(sql)",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "source": {
                "expression": "request.GET.get('term')",
                "file_path": "views/handlers.py",
                "line": 12,
                "column": 8,
            },
            "call_chain": [
                {
                    "caller_function": "search_view",
                    "callee_function": "format_search_sql",
                    "caller_file": "views/handlers.py",
                    "callee_file": "db/queries.py",
                    "call_site_line": 18,
                    "call_site_col": 14,
                    "argument_index": 0,
                    "callee_param_name": "term",
                    "taint_action": "ARG_TO_RETURN",
                }
            ],
            "sink": {
                "callee": "cursor.execute",
                "file_path": "views/handlers.py",
                "line": 25,
                "column": 8,
            },
            "path_summary": "term -> format_search_sql() -> cursor.execute()",
            "total_depth": 1,
            "files_involved": ["views/handlers.py", "db/queries.py"],
        },
    )

    result = AnalysisResult(
        id="sarif-run-15",
        status=AnalysisStatus.COMPLETED,
        repository=RepositoryInfo(name="sarif_test_repo", local_path="/local/sarif_test"),
        metadata=AnalysisMetadata(),
        security_findings=[finding],
        architecture_findings=[],
    )

    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    doc = json.loads(sarif_str)

    run = doc["runs"][0]
    # Verify artifacts list includes both files
    artifact_uris = [a["location"]["uri"] for a in run["artifacts"]]
    assert "views/handlers.py" in artifact_uris
    assert "db/queries.py" in artifact_uris

    # Verify result codeFlows
    sarif_finding = run["results"][0]
    assert "codeFlows" in sarif_finding
    thread_flow = sarif_finding["codeFlows"][0]["threadFlows"][0]
    locations = thread_flow["locations"]

    # Must contain at least: Source, Call step, Sink
    assert len(locations) >= 3

    # Step 1: Source
    assert locations[0]["importance"] == "essential"
    assert "Source:" in locations[0]["message"]["text"]
    assert locations[0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "views/handlers.py"
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 12

    # Step 2: Call step
    assert locations[1]["importance"] == "important"
    assert "format_search_sql" in locations[1]["message"]["text"]
    assert locations[1]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "views/handlers.py"
    assert locations[1]["location"]["physicalLocation"]["region"]["startLine"] == 18

    # Step 3: Sink
    assert locations[2]["importance"] == "essential"
    assert "cursor.execute" in locations[2]["message"]["text"]
    assert locations[2]["location"]["physicalLocation"]["region"]["startLine"] == 25
