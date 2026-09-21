"""Tests for Phase 8 CLI filtering flags (--severity, --category, --rule)."""

import json
import pytest

from analyzer.cli.main import main


def test_cli_filter_by_severity_high(sample_repo_path, capsys):
    """Verify --severity HIGH returns only HIGH and CRITICAL findings."""
    ret = main(["analyze", str(sample_repo_path), "--severity", "HIGH", "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    all_findings = data["security_findings"] + data["architecture_findings"]
    assert len(all_findings) > 0
    for f in all_findings:
        assert f["severity"] in ["HIGH", "CRITICAL"]


def test_cli_filter_by_category_security(sample_repo_path, capsys):
    """Verify --category SECURITY includes zero architecture findings."""
    ret = main(["analyze", str(sample_repo_path), "--category", "SECURITY", "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert len(data["architecture_findings"]) == 0
    assert data["architecture_summary"]["total_findings"] == 0


def test_cli_filter_by_category_architecture(sample_repo_path, capsys):
    """Verify --category ARCHITECTURE includes zero security findings."""
    ret = main(["analyze", str(sample_repo_path), "--category", "ARCHITECTURE", "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert len(data["security_findings"]) == 0
    assert data["security_summary"]["total"] == 0
    assert len(data["architecture_findings"]) > 0


def test_cli_filter_by_rule_id(sample_repo_path, capsys):
    """Verify --rule filter retains only findings with the requested rule ID."""
    ret = main(["analyze", str(sample_repo_path), "--rule", "ARC-001", "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    all_findings = data["security_findings"] + data["architecture_findings"]
    assert len(all_findings) > 0
    for f in all_findings:
        assert f["rule_id"] == "ARC-001"


def test_cli_filter_combination(sample_repo_path, capsys):
    """Verify combining --category, --severity, and --rule works deterministically."""
    ret = main([
        "analyze",
        str(sample_repo_path),
        "--category", "ARCHITECTURE",
        "--severity", "HIGH",
        "--rule", "ARC-001",
        "--format", "json",
    ])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert len(data["security_findings"]) == 0
    for f in data["architecture_findings"]:
        assert f["rule_id"] == "ARC-001"
        assert f["severity"] == "HIGH"
