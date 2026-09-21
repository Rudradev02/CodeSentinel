"""Unit tests for Phase 9 SARIF v2.1.0 report generation."""

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
from analyzer.reporting.sarif import SarifReporter


def test_sarif_empty_findings():
    """Verify SARIF generation with zero findings produces a valid v2.1.0 run."""
    repo_info = RepositoryInfo(
        name="test-repo",
        local_path="/repo",
        total_files=5,
        detected_languages={"python": 5},
    )
    result = AnalysisResult(
        repository=repo_info,
        security_findings=[],
        architecture_findings=[],
    )

    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    sarif_dict = json.loads(sarif_str)

    assert sarif_dict["version"] == "2.1.0"
    assert sarif_dict["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert len(sarif_dict["runs"]) == 1

    run = sarif_dict["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeSentinel"
    assert len(run["results"]) == 0
    assert "versionControlProvenance" not in run


def test_sarif_findings_mapping_and_severity():
    """Verify rules, results, locations, and severity levels are correctly mapped."""
    repo_info = RepositoryInfo(
        name="test-repo",
        local_path="/repo",
        total_files=10,
        detected_languages={"python": 10},
        commit_hash="abcdef1234567890abcdef1234567890abcdef12",
        branch="main",
        is_dirty=False,
    )
    f1 = Finding(
        id="f1",
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secret Key",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(
            file_path="src/config\\secrets.py",  # Backslashes should normalize
            line_start=15,
            line_end=15,
            col_start=4,
            col_end=20,
        ),
        code_snippet="aws_key = 'AKIA...'",
        description="Found AWS secret access key",
        remediation="Use environment variables instead.",
    )
    f2 = Finding(
        id="f2",
        rule_id="ARC-001",
        rule_name="Circular Module Dependency",
        category=FindingCategory.ARCHITECTURE,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(
            file_path="src/a.py",
            line_start=1,
            line_end=1,
        ),
        code_snippet="import b",
        description="Cycle between a and b",
        remediation="Refactor shared components into separate module.",
    )

    result = AnalysisResult(
        repository=repo_info,
        security_findings=[f1],
        architecture_findings=[f2],
    )

    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    data = json.loads(sarif_str)

    run = data["runs"][0]
    driver = run["tool"]["driver"]

    # Rule definitions
    rules = {r["id"]: r for r in driver["rules"]}
    assert "SEC-PY-001" in rules
    assert "ARC-001" in rules

    # Results mapped
    sarif_results = run["results"]
    assert len(sarif_results) == 2

    r1 = next(r for r in sarif_results if r["ruleId"] == "SEC-PY-001")
    assert r1["level"] == "error"
    assert r1["message"]["text"] == "Hardcoded Secret Key"

    loc = r1["locations"][0]["physicalLocation"]
    # Path normalized to forward slashes
    assert loc["artifactLocation"]["uri"] == "src/config/secrets.py"
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert loc["region"]["startLine"] == 15
    assert loc["region"]["startColumn"] == 5  # 0-based col_start 4 -> 1-based startColumn 5
    assert loc["region"]["endColumn"] == 21
    assert loc["region"]["snippet"]["text"] == "aws_key = 'AKIA...'"

    # Git provenance present
    assert "versionControlProvenance" in run
    vcs = run["versionControlProvenance"][0]
    assert vcs["revisionId"] == "abcdef1234567890abcdef1234567890abcdef12"
    assert vcs["branch"] == "main"
    assert vcs["properties"]["isDirty"] is False
