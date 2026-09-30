"""Unit tests for Phase 30.2 Secret Scrubber, Evidence Grounding, and AI Security."""

from pathlib import Path
import tempfile
import pytest

from backend.app.services.ai.scrubber import (
    REDACTED_AWS_KEY,
    REDACTED_GITHUB_TOKEN,
    REDACTED_SECRET,
    REDACTED_SLACK_TOKEN,
    REDACTED_TOKEN,
    SecretScrubber,
)
from backend.app.services.ai.validator import SemanticValidator


def test_secret_scrubber_detects_expanded_tokens():
    """Verify SecretScrubber redacts modern token types and formats."""
    # AWS key
    assert SecretScrubber.scrub("aws_key = AKIAIOSFODNN7EXAMPLE") == f"aws_key = {REDACTED_AWS_KEY}"
    # Standard GitHub PAT
    assert SecretScrubber.scrub("token: ghp_123456789012345678901234567890123456") == f"token: {REDACTED_GITHUB_TOKEN}"
    # Fine-grained GitHub PAT
    fg_pat = "github_pat_11AEXAMPLE01234567890_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123"
    assert SecretScrubber.scrub(f"pat = {fg_pat}") == f"pat = {REDACTED_GITHUB_TOKEN}"
    # Slack token
    assert SecretScrubber.scrub("xoxb-1234567890-123456789012-abcdef123456") == REDACTED_SLACK_TOKEN
    # Anthropic key
    assert SecretScrubber.scrub("key = sk-ant-api03-1234567890abcdef1234567890abcdef-abcdef123456") == f"key = {REDACTED_SECRET}"
    # OpenAI project key
    assert SecretScrubber.scrub("key = sk-proj-1234567890abcdef1234567890abcdef12345678") == f"key = {REDACTED_SECRET}"


def test_shannon_entropy_calculation():
    """Verify compute_entropy distinguishes random strings from repetitive ones."""
    # Repetitive string has low entropy
    low_entropy = SecretScrubber.compute_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High randomness base64/hex token has high entropy (> 4.0)
    high_entropy = SecretScrubber.compute_entropy("a8F9z!2Kx$9Lq#1Pz@8Wm%4Jn^7Vb*3Q")
    assert high_entropy > 4.5


def test_evidence_grounding_validates_existing_symbol():
    """Verify validate_evidence_grounding approves symbols present in source."""
    source = """
    func handle(query string) {
        clean := sanitize(query)
        db.Exec(clean)
    }
    """
    is_grounded, unverified = SemanticValidator.validate_evidence_grounding(
        target_finding_id="find-1",
        target_file_path="main.go",
        line_start=2,
        line_end=4,
        enclosing_source=source,
        cited_symbols=["sanitize", "db.Exec"],
    )
    assert is_grounded is True
    assert len(unverified) == 0


def test_evidence_grounding_flags_hallucinated_symbol():
    """Verify validate_evidence_grounding catches and flags hallucinated sanitizers."""
    source = """
    def execute_user_query(user_input):
        db.raw_query(user_input)
    """
    is_grounded, unverified = SemanticValidator.validate_evidence_grounding(
        target_finding_id="find-2",
        target_file_path="app.py",
        line_start=2,
        line_end=3,
        enclosing_source=source,
        cited_symbols=["validate_and_escape_sql"],  # Hallucinated by LLM
    )
    assert is_grounded is False
    assert any("validate_and_escape_sql" in u for u in unverified)
