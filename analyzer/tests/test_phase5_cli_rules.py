"""Phase 5 tests for CLI 'rules' command inspection."""

import json
from io import StringIO
import sys
import pytest

from analyzer.cli.main import main


def test_cli_rules_list_terminal(capsys):
    ret = main(["rules"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "REGISTERED STATIC ANALYSIS RULES" in captured.out
    assert "SEC-PY-001" in captured.out
    assert "ARC-001" in captured.out
    assert "Total Registered Rules: 27" in captured.out


def test_cli_rules_list_json(capsys):
    ret = main(["rules", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) == 27
    ids = [d["rule_id"] for d in data]
    assert "SEC-PY-001" in ids
    assert "ARC-001" in ids


def test_cli_rules_detail_terminal_security(capsys):
    ret = main(["rules", "SEC-PY-001"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "RULE SPECIFICATION: SEC-PY-001" in captured.out
    assert "CWE-798" in captured.out
    assert "Rationale:" in captured.out


def test_cli_rules_detail_terminal_architecture(capsys):
    ret = main(["rules", "ARC-001"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "RULE SPECIFICATION: ARC-001" in captured.out
    assert "Circular Dependency" in captured.out
    assert "Rationale:" in captured.out


def test_cli_rules_detail_json(capsys):
    ret = main(["rules", "SEC-PY-001", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["rule_id"] == "SEC-PY-001"
    assert data["severity"] == "HIGH"
    assert data["rationale"] is not None


def test_cli_rules_unknown_rule_rejected(capsys):
    ret = main(["rules", "UNKNOWN-999"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error: Unknown rule ID 'UNKNOWN-999'" in captured.err
