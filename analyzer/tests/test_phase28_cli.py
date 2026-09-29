"""Integration tests for Phase 28 CLI workspace commands."""

import json
from pathlib import Path
import pytest

from analyzer.cli.main import main


def test_cli_workspace_init(tmp_path: Path, capsys):
    """Test 'codesentinel workspace init' generates a valid manifest file."""
    manifest_file = tmp_path / "custom-workspace.yaml"
    exit_code = main(["workspace", "init", "--name", "Fintech Cloud", "--manifest", str(manifest_file)])
    assert exit_code == 0
    assert manifest_file.exists()
    content = manifest_file.read_text(encoding="utf-8")
    assert 'name: "Fintech Cloud"' in content
    assert "repositories:" in content
    assert "core-library" in content
    assert "api-gateway" in content


def test_cli_workspace_graph(tmp_path: Path, capsys):
    """Test 'codesentinel workspace graph' renders topological dependency waves."""
    manifest_file = tmp_path / "codesentinel-workspace.yaml"
    init_code = main(["workspace", "init", "--manifest", str(manifest_file)])
    assert init_code == 0

    # 1. Terminal format
    capsys.readouterr()  # clear capture
    exit_code = main(["workspace", "graph", str(manifest_file)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WORKSPACE TOPOLOGY DAG" in captured.out
    assert "Execution Schedule (Topological Waves):" in captured.out
    assert "Wave 1" in captured.out
    assert "Wave 2" in captured.out

    # 2. JSON format
    exit_code_json = main(["workspace", "graph", str(manifest_file), "--format", "json"])
    assert exit_code_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert "execution_waves" in data
    assert len(data["execution_waves"]) == 2


def test_cli_workspace_scan_and_verify(tmp_path: Path, capsys):
    """Test 'codesentinel workspace scan' and 'verify-attestation' end-to-end."""
    # Setup test repos
    repo1 = tmp_path / "packages" / "core"
    repo1.mkdir(parents=True)
    (repo1 / "main.py").write_text("def sanitize(x): return x.strip()", encoding="utf-8")

    repo2 = tmp_path / "services" / "gateway"
    repo2.mkdir(parents=True)
    (repo2 / "server.py").write_text("def handle_request(): pass", encoding="utf-8")

    manifest_file = tmp_path / "codesentinel-workspace.yaml"
    main(["workspace", "init", "--manifest", str(manifest_file)])

    audit_dir = tmp_path / "audit-results"
    scan_code = main([
        "workspace", "scan", str(manifest_file),
        "--output-dir", str(audit_dir),
        "--key", "secret-test-key-2026",
    ])
    assert scan_code == 0

    comp_file = audit_dir / "workspace-compliance.json"
    attest_file = audit_dir / "workspace-attestation.json"
    assert comp_file.exists()
    assert attest_file.exists()

    # Verify attestation via CLI
    capsys.readouterr()
    verify_code = main([
        "workspace", "verify-attestation", str(attest_file),
        "--key", "secret-test-key-2026",
    ])
    assert verify_code == 0
    captured = capsys.readouterr()
    assert "[WORKSPACE ATTESTATION VERIFIED]" in captured.out
