"""Tests for codesentinel compliance CLI subcommands."""

import json
from pathlib import Path
import pytest
from analyzer.cli.main import build_parser, main


def test_compliance_subcommand_help():
    """Verify compliance subcommand is registered in CLI parser."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["compliance", "check", "--help"])
    assert exc_info.value.code == 0


def test_compliance_check_cli(tmp_path: Path):
    """Verify codesentinel compliance check runs successfully on target folder."""
    sample_file = tmp_path / "main.py"
    sample_file.write_text("x = 1\n", encoding="utf-8")

    code = main(["compliance", "check", str(tmp_path), "--framework", "pci-dss"])
    assert code == 0


def test_compliance_attest_and_verify_cli(tmp_path: Path):
    """Verify codesentinel compliance attest generates file, and verify-attestation validates it."""
    sample_file = tmp_path / "service.py"
    sample_file.write_text("import os\ndef test(): pass\n", encoding="utf-8")

    attest_file = tmp_path / "scan.attestation.json"
    attest_code = main([
        "compliance",
        "attest",
        str(tmp_path),
        "--key",
        "my-secret-key-123",
        "-o",
        str(attest_file),
    ])
    assert attest_code == 0
    assert attest_file.exists()

    verify_code = main([
        "compliance",
        "verify-attestation",
        str(attest_file),
        "--key",
        "my-secret-key-123",
    ])
    assert verify_code == 0

    wrong_key_code = main([
        "compliance",
        "verify-attestation",
        str(attest_file),
        "--key",
        "wrong-secret-key",
    ])
    assert wrong_key_code == 1


def test_analyze_with_compliance_and_attestation(tmp_path: Path):
    """Verify codesentinel analyze accepts --compliance and --attest flags."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("print('hello')\n", encoding="utf-8")

    code = main([
        "analyze",
        str(tmp_path),
        "--compliance",
        "pci-dss,hipaa",
        "--attest",
        "--signing-key",
        "test-key",
    ])
    assert code == 0
