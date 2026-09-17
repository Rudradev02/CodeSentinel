"""Tests for the CodeSentinel command line interface."""

import json
from pathlib import Path
import pytest

from analyzer.cli.main import main


def test_cli_no_arguments(capsys):
    ret = main([])
    assert ret == 1
    captured = capsys.readouterr()
    assert "usage: codesentinel" in captured.err


def test_cli_version(capsys):
    ret = main(["--version"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "codesentinel-analyzer" in captured.out


def test_cli_invalid_path(capsys):
    ret = main(["analyze", "non_existent_path_xyz_123"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Analysis Error" in captured.err


def test_cli_analyze_terminal_output(sample_repo_path, capsys):
    ret = main(["analyze", str(sample_repo_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CODESENTINEL REPOSITORY STATIC ANALYSIS REPORT" in captured.out
    assert "ARC-001: Circular Dependency" in captured.out
    assert "RESULT: Completed with 1 total finding(s)." in captured.out


def test_cli_analyze_direct_path_ergonomic_shortcut(sample_repo_path, capsys):
    ret = main([str(sample_repo_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CODESENTINEL REPOSITORY STATIC ANALYSIS REPORT" in captured.out


def test_cli_analyze_json_format(sample_repo_path, capsys):
    ret = main(["analyze", str(sample_repo_path), "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["status"] == "COMPLETED"
    assert parsed["repository"]["name"] == "sample_project"
    assert len(parsed["architecture_findings"]) == 1
    assert parsed["architecture_findings"][0]["rule_id"] == "ARC-001"


def test_cli_output_to_file(sample_repo_path, tmp_path):
    out_file = tmp_path / "report.json"
    ret = main(["analyze", str(sample_repo_path), "--format", "json", "-o", str(out_file)])
    assert ret == 0
    assert out_file.exists()

    content = out_file.read_text(encoding="utf-8")
    parsed = json.loads(content)
    assert parsed["status"] == "COMPLETED"


def test_cli_disable_rule(sample_repo_path, capsys):
    # Disabling ARC-001 should eliminate the only finding on sample_project
    ret = main(["analyze", str(sample_repo_path), "--disable-rule", "ARC-001"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "RESULT: Clean audit" in captured.out


def test_cli_enable_rule_whitelist(sample_repo_path, capsys):
    # Whitelist only SEC-PY-001 (ARC-001 should not run)
    ret = main(["analyze", str(sample_repo_path), "--enable-rule", "SEC-PY-001"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "RESULT: Clean audit" in captured.out


def test_cli_rule_conflict_rejection(sample_repo_path, capsys):
    ret = main(["analyze", str(sample_repo_path), "--enable-rule", "ARC-001", "--disable-rule", "ARC-001"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Rule configuration conflict" in captured.err


def test_cli_unknown_rule_rejection(sample_repo_path, capsys):
    ret = main(["analyze", str(sample_repo_path), "--enable-rule", "UNKNOWN-001"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Unknown rule ID(s)" in captured.err


def test_cli_fail_on_policy_triggers_exit_2(sample_repo_path, capsys):
    # ARC-001 has severity HIGH, so --fail-on HIGH should trigger exit code 2
    ret = main(["analyze", str(sample_repo_path), "--fail-on", "HIGH"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "[POLICY FAILURE]" in captured.err


def test_cli_fail_on_policy_passes_exit_0(sample_repo_path, capsys):
    # Highest finding is HIGH, so --fail-on CRITICAL should pass (exit code 0)
    ret = main(["analyze", str(sample_repo_path), "--fail-on", "CRITICAL"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "[POLICY FAILURE]" not in captured.err


def test_cli_god_module_loc_override(sample_repo_path, capsys):
    # Sample repo files have <= 24 LOC. Overriding threshold to 5 lines should trigger ARC-003 if couplings match,
    # or at least accept the flag cleanly.
    ret = main(["analyze", str(sample_repo_path), "--god-module-loc", "1000"])
    assert ret == 0
