"""Tests for Phase 9 CLI baseline comparison, SARIF format, and regression gating."""

import json
from pathlib import Path
import pytest
from analyzer.cli.main import main
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisResult, RepositoryInfo


def _create_sample_report(path: Path, finding_rules: list[tuple[str, FindingSeverity]], commit: str = "c1") -> Path:
    repo = RepositoryInfo(
        name="test-repo",
        local_path=str(path.parent),
        total_files=2,
        detected_languages={"python": 2},
        commit_hash=commit,
    )
    findings = []
    for idx, (rule_id, sev) in enumerate(finding_rules):
        findings.append(
            Finding(
                id=f"f-{rule_id}-{idx}",
                rule_id=rule_id,
                rule_name=f"Rule {rule_id}",
                category=FindingCategory.SECURITY,
                evidence_type=EvidenceType.DETERMINISTIC,
                severity=sev,
                confidence=FindingConfidence.HIGH,
                location=SourceLocation(file_path="app.py", line_start=10 + idx, line_end=10 + idx),
                code_snippet=f"vulnerability_{idx}()",
                description=f"Violation {rule_id}",
                remediation="Fix it",
            )
        )
    result = AnalysisResult(
        repository=repo,
        security_findings=findings,
    )
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_cli_sarif_output(tmp_path: Path, capsys):
    """Verify codesentinel analyze --format sarif produces valid SARIF JSON."""
    test_file = tmp_path / "hello.py"
    test_file.write_text("print('hello')\n", encoding="utf-8")

    exit_code = main(["analyze", str(tmp_path), "--format", "sarif"])
    assert exit_code == 0

    captured = capsys.readouterr()
    sarif_data = json.loads(captured.out)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "CodeSentinel"


def test_cli_compare_subcommand(tmp_path: Path, capsys):
    """Verify codesentinel compare baseline.json current.json --format json."""
    baseline_file = _create_sample_report(
        tmp_path / "base.json",
        [("SEC-PY-001", FindingSeverity.HIGH)],
        commit="commit-1",
    )
    current_file = _create_sample_report(
        tmp_path / "curr.json",
        [("SEC-PY-001", FindingSeverity.HIGH), ("SEC-PY-002", FindingSeverity.CRITICAL)],
        commit="commit-2",
    )

    exit_code = main(["compare", str(baseline_file), str(current_file), "--format", "json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    diff_data = json.loads(captured.out)
    assert diff_data["summary"]["total_baseline"] == 1
    assert diff_data["summary"]["total_current"] == 2
    assert diff_data["summary"]["unchanged_count"] == 1
    assert diff_data["summary"]["new_count"] == 1
    assert diff_data["summary"]["new_by_severity"].get("CRITICAL") == 1


def test_cli_compare_fail_on_regression(tmp_path: Path):
    """Verify --fail-on-regression triggers exit code 2 on new violation."""
    baseline_file = _create_sample_report(
        tmp_path / "base.json",
        [("SEC-PY-001", FindingSeverity.HIGH)],
    )
    current_file = _create_sample_report(
        tmp_path / "curr.json",
        [("SEC-PY-001", FindingSeverity.HIGH), ("SEC-PY-002", FindingSeverity.HIGH)],
    )

    # SEC-PY-002 is a newly introduced HIGH severity finding
    exit_code = main([
        "compare",
        str(baseline_file),
        str(current_file),
        "--fail-on-regression",
        "HIGH",
    ])
    assert exit_code == 2

    # CRITICAL should pass because the new finding is only HIGH
    exit_code_pass = main([
        "compare",
        str(baseline_file),
        str(current_file),
        "--fail-on-regression",
        "CRITICAL",
    ])
    assert exit_code_pass == 0
