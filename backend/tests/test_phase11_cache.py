"""Unit tests for Phase 11 Redis Analysis Cache Service."""

from unittest.mock import MagicMock, patch
import pytest

from backend.app.services.cache import AnalysisCacheService


def test_cache_miss_on_empty_or_unknown_commit():
    """Verify cache returns None when commit hash is empty, dirty, or unknown."""
    assert AnalysisCacheService.get_cached_snapshot_id("repo-1", "") is None
    assert AnalysisCacheService.get_cached_snapshot_id("repo-1", "unknown") is None
    assert AnalysisCacheService.get_cached_snapshot_id("repo-1", None) is None


def test_cache_hit_and_set():
    """Verify cache stores and retrieves snapshot IDs when Redis is available."""
    mock_redis = MagicMock()
    mock_redis.get.return_value = "snapshot-uuid-cached-99"

    with patch("backend.app.services.cache.get_redis_client", return_value=mock_redis):
        # 1. Store
        AnalysisCacheService.set_cached_snapshot_id(
            repository_id="repo-123",
            commit_hash="a1b2c3d4",
            snapshot_id="snapshot-uuid-cached-99",
            ttl_seconds=3600,
        )
        mock_redis.set.assert_called_once_with(
            "codesentinel:cache:analysis:repo-123:a1b2c3d4",
            "snapshot-uuid-cached-99",
            ex=3600,
        )

        # 2. Retrieve
        val = AnalysisCacheService.get_cached_snapshot_id("repo-123", "a1b2c3d4")
        assert val == "snapshot-uuid-cached-99"
        mock_redis.get.assert_called_once_with("codesentinel:cache:analysis:repo-123:a1b2c3d4")


def test_cache_invalidation():
    """Verify invalidation deletes matching keys for the repository."""
    mock_redis = MagicMock()
    mock_redis.keys.return_value = [
        "codesentinel:cache:analysis:repo-del:hash1",
        "codesentinel:cache:analysis:repo-del:hash2",
    ]

    with patch("backend.app.services.cache.get_redis_client", return_value=mock_redis):
        AnalysisCacheService.invalidate_repository("repo-del")
        mock_redis.keys.assert_called_once_with("codesentinel:cache:analysis:repo-del:*")
        mock_redis.delete.assert_called_once_with(
            "codesentinel:cache:analysis:repo-del:hash1",
            "codesentinel:cache:analysis:repo-del:hash2",
        )
