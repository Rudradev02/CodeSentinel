"""Unit tests for Phase 21 persistent and in-memory cache architecture."""

import gzip
import json
from pathlib import Path
import time
import pytest

from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache, NullAnalysisCache
from analyzer.incremental.keys import build_l1_key, build_l2_key, compute_repo_namespace_id


class TestKeysAndNamespace:
    """Verifies deterministic cache key and repository namespace derivation."""

    def test_repo_namespace_git(self):
        ns1 = compute_repo_namespace_id(
            repo_root="/dummy",
            remote_url="https://github.com/org/repo.git",
            root_commit="abcdef123456",
        )
        ns2 = compute_repo_namespace_id(
            repo_root="/other",
            remote_url="https://github.com/org/repo.git",
            root_commit="abcdef123456",
        )
        assert ns1 == ns2
        assert len(ns1) == 16

    def test_repo_namespace_path(self, tmp_path):
        ns = compute_repo_namespace_id(repo_root=tmp_path)
        assert len(ns) == 16

    def test_layer_keys_deterministic(self):
        k1 = build_l1_key("repo123", "src/main.py")
        k2 = build_l1_key("repo123", "src/main.py")
        k3 = build_l1_key("repo123", "src/other.py")
        assert k1 == k2
        assert k1 != k3
        assert len(k1) == 64


class TestInMemoryCache:
    """Verifies operations on the in-memory cache."""

    def test_in_memory_crud(self):
        cache = InMemoryAnalysisCache()
        assert cache.get("L1", "key1") is None
        assert cache.has("L1", "key1") is False

        cache.set("L1", "key1", {"data": 42})
        assert cache.has("L1", "key1") is True
        assert cache.get("L1", "key1") == {"data": 42}

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["entries"] == 1

        assert cache.delete("L1", "key1") is True
        assert cache.get("L1", "key1") is None


class TestDiskCache:
    """Verifies disk-backed persistent caching, atomic writes, and corruption recovery."""

    def test_disk_cache_roundtrip(self, tmp_path):
        cache = DiskAnalysisCache(cache_root=tmp_path, repo_namespace_id="test_repo")
        key = "sample_key_123"
        payload = {"ast": "FunctionDef", "name": "foo", "lines": [1, 2, 3]}

        assert cache.get("L2", key) is None
        assert cache.set("L2", key, payload, metadata={"source": "test"}) is True
        assert cache.has("L2", key) is True

        retrieved = cache.get("L2", key)
        assert retrieved == payload

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["entries"] == 1

    def test_disk_cache_checksum_corruption_recovery(self, tmp_path):
        cache = DiskAnalysisCache(cache_root=tmp_path, repo_namespace_id="test_repo")
        key = "corrupt_key"
        payload = {"value": 100}
        cache.set("L4", key, payload)

        # Intentionally tamper with the stored payload on disk without updating checksum
        target_path = cache._artifact_path("L4", key)
        envelope = json.loads(target_path.read_text(encoding="utf-8"))
        envelope["payload"]["value"] = 999  # tampered
        target_path.write_text(json.dumps(envelope), encoding="utf-8")

        # Must detect checksum mismatch, treat as safe miss, and remove corrupted file
        retrieved = cache.get("L4", key)
        assert retrieved is None
        assert not target_path.exists()

    def test_disk_cache_invalid_json_recovery(self, tmp_path):
        cache = DiskAnalysisCache(cache_root=tmp_path, repo_namespace_id="test_repo")
        key = "broken_json"
        cache.set("L7", key, {"ok": True})

        # Truncate file on disk to simulate power-loss truncation
        target_path = cache._artifact_path("L7", key)
        target_path.write_text("{\"schema_version\": \"1.", encoding="utf-8")

        # Must catch JSONDecodeError safely, treat as miss, and clean up
        retrieved = cache.get("L7", key)
        assert retrieved is None
        assert not target_path.exists()

    def test_disk_cache_schema_mismatch_recovery(self, tmp_path):
        cache = DiskAnalysisCache(cache_root=tmp_path, repo_namespace_id="test_repo")
        key = "old_schema"
        cache.set("L5", key, {"data": "test"})

        target_path = cache._artifact_path("L5", key)
        envelope = json.loads(target_path.read_text(encoding="utf-8"))
        envelope["schema_version"] = "99.0.0"  # Incompatible version
        target_path.write_text(json.dumps(envelope), encoding="utf-8")

        retrieved = cache.get("L5", key)
        assert retrieved is None
        assert not target_path.exists()

    def test_disk_cache_eviction(self, tmp_path):
        # Cache with maximum of 2 entries
        cache = DiskAnalysisCache(
            cache_root=tmp_path,
            repo_namespace_id="test_repo",
            max_entries=2,
            max_cache_size_bytes=1000000,
        )

        cache.set("L1", "k1", {"val": 1})
        time.sleep(0.01)
        cache.set("L1", "k2", {"val": 2})
        time.sleep(0.01)
        cache.set("L1", "k3", {"val": 3})

        # Oldest entry k1 should have been evicted to satisfy max_entries=2
        stats = cache.get_stats()
        assert stats["entries"] <= 2
        assert cache.has("L1", "k3") is True
