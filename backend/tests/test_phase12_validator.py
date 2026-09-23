"""Unit tests for SemanticValidator and patch safety gating."""

from pathlib import Path
import tempfile
import pytest

from backend.app.services.ai.validator import SemanticValidationError, SemanticValidator


@pytest.fixture
def mock_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        target = root / "app" / "server.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("app.run(debug=True)", encoding="utf-8")
        yield root


def test_valid_enrichment_and_patch(mock_repo: Path):
    """Verify valid JSON schema and clean unified diff pass semantic validation."""
    raw_json = {
        "finding_id": "target-id-1",
        "is_likely_true_positive": True,
        "confidence_score": 0.92,
        "risk_summary": "Debug mode enabled in production",
        "technical_reasoning": "debug=True allows arbitrary code execution via Werkzeug pin.",
        "assumptions_and_limitations": ["Assumes app.run is executed in production context"],
        "prescribed_remediation": "Set debug=False or use environment variable.",
        "proposed_patch": {
            "file_path": "app/server.py",
            "original_snippet": "app.run(debug=True)",
            "patched_snippet": "app.run(debug=False)",
            "unified_diff": "--- a/app/server.py\n+++ b/app/server.py\n@@ -1,1 +1,1 @@\n-app.run(debug=True)\n+app.run(debug=False)\n",
            "explanation": "Disables interactive debugger",
        },
    }

    validated = SemanticValidator.validate_and_sanitize(
        raw_json=raw_json,
        target_finding_id="target-id-1",
        target_file_path="app/server.py",
        repo_root=mock_repo,
    )

    assert validated.finding_id == "target-id-1"
    assert validated.is_likely_true_positive is True
    assert validated.proposed_patch is not None
    assert validated.proposed_patch.patched_snippet == "app.run(debug=False)"


def test_patch_path_traversal_discarded(mock_repo: Path):
    """Verify patch with path traversal is discarded while explanation is retained."""
    raw_json = {
        "finding_id": "target-id-1",
        "is_likely_true_positive": True,
        "confidence_score": 0.85,
        "risk_summary": "Risk summary",
        "technical_reasoning": "Reasoning",
        "assumptions_and_limitations": [],
        "prescribed_remediation": "Guidance",
        "proposed_patch": {
            "file_path": "../outside.py",
            "original_snippet": "bad()",
            "patched_snippet": "good()",
            "unified_diff": "--- a/../outside.py\n+++ b/../outside.py\n@@ ... @@",
            "explanation": "Malicious patch",
        },
    }

    validated = SemanticValidator.validate_and_sanitize(
        raw_json=raw_json,
        target_finding_id="target-id-1",
        target_file_path="app/server.py",
        repo_root=mock_repo,
    )

    # Patch must be discarded
    assert validated.proposed_patch is None
    # Textual explanation must still be preserved
    assert validated.risk_summary == "Risk summary"


def test_patch_introducing_secret_discarded(mock_repo: Path):
    """Verify patch proposing new hardcoded secret is discarded."""
    raw_json = {
        "finding_id": "target-id-1",
        "is_likely_true_positive": True,
        "confidence_score": 0.80,
        "risk_summary": "Issue",
        "technical_reasoning": "Reason",
        "assumptions_and_limitations": [],
        "prescribed_remediation": "Fix",
        "proposed_patch": {
            "file_path": "app/server.py",
            "original_snippet": "app.run()",
            "patched_snippet": "api_key = 'sk-1234567890abcdef1234567890abcdef1234'\napp.run()",
            "unified_diff": "--- a/app/server.py\n+++ b/app/server.py\n@@ -1,1 +1,2 @@\n-app.run()\n+api_key = 'sk-1234567890abcdef1234567890abcdef1234'\n+app.run()\n",
            "explanation": "Unsafe patch with key",
        },
    }

    validated = SemanticValidator.validate_and_sanitize(
        raw_json=raw_json,
        target_finding_id="target-id-1",
        target_file_path="app/server.py",
        repo_root=mock_repo,
    )

    assert validated.proposed_patch is None
