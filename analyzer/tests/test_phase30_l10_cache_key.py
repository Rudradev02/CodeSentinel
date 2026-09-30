"""Unit tests for Phase 30.2 L10 AI Cache Key Derivation."""

from analyzer.incremental.keys import build_l10_key


def test_build_l10_key_determinism():
    """Verify build_l10_key generates stable, deterministic SHA-256 hashes."""
    key1 = build_l10_key(
        repo_namespace="repo-123",
        finding_primary_hash="hash-abc",
        evidence_hash="ev-123",
        source_context_hash="src-456",
        prompt_version="v2",
        model_name="claude-3.5-sonnet",
        provider_name="openrouter",
    )
    key2 = build_l10_key(
        repo_namespace="repo-123",
        finding_primary_hash="hash-abc",
        evidence_hash="ev-123",
        source_context_hash="src-456",
        prompt_version="v2",
        model_name="claude-3.5-sonnet",
        provider_name="openrouter",
    )
    assert key1 == key2
    assert len(key1) == 64


def test_build_l10_key_invalidation_on_context_change():
    """Verify changing source code context or model shifts L10 cache key."""
    base_key = build_l10_key(
        repo_namespace="repo-123",
        finding_primary_hash="hash-abc",
        evidence_hash="ev-123",
        source_context_hash="src-v1",
        prompt_version="v2",
        model_name="claude-3.5-sonnet",
        provider_name="openrouter",
    )

    # Shift source context
    changed_src_key = build_l10_key(
        repo_namespace="repo-123",
        finding_primary_hash="hash-abc",
        evidence_hash="ev-123",
        source_context_hash="src-v2",
        prompt_version="v2",
        model_name="claude-3.5-sonnet",
        provider_name="openrouter",
    )
    assert base_key != changed_src_key

    # Shift model
    changed_model_key = build_l10_key(
        repo_namespace="repo-123",
        finding_primary_hash="hash-abc",
        evidence_hash="ev-123",
        source_context_hash="src-v1",
        prompt_version="v2",
        model_name="gpt-4o",
        provider_name="openrouter",
    )
    assert base_key != changed_model_key
