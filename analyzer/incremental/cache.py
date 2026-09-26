"""Persistent and in-memory layered analysis cache engine (Phase 21)."""

from abc import ABC, abstractmethod
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Optional
import uuid

logger = logging.getLogger(__name__)

CACHE_ENVELOPE_SCHEMA_VERSION = "1.0.0"


class AnalysisCache(ABC):
    """Abstract interface for storing and retrieving layered analysis artifacts."""

    @abstractmethod
    def get(self, layer: str, key: str) -> Optional[Any]:
        """Retrieve cached artifact if valid; returns None on cache miss or error."""
        pass

    @abstractmethod
    def set(self, layer: str, key: str, value: Any, metadata: Optional[dict[str, Any]] = None) -> bool:
        """Store artifact payload under specified layer and key."""
        pass

    @abstractmethod
    def has(self, layer: str, key: str) -> bool:
        """Check if artifact exists and is valid."""
        pass

    @abstractmethod
    def delete(self, layer: str, key: str) -> bool:
        """Evict artifact from cache."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all artifacts in this cache namespace."""
        pass

    @abstractmethod
    def get_stats(self) -> dict[str, Any]:
        """Return cache hit, miss, and storage telemetry."""
        pass


class NullAnalysisCache(AnalysisCache):
    """Null object implementation used when caching is disabled (--no-cache)."""

    def __init__(self):
        self._stats = {"hits": 0, "misses": 0, "entries": 0, "size_bytes": 0}

    def get(self, layer: str, key: str) -> Optional[Any]:
        self._stats["misses"] += 1
        return None

    def set(self, layer: str, key: str, value: Any, metadata: Optional[dict[str, Any]] = None) -> bool:
        return True

    def has(self, layer: str, key: str) -> bool:
        return False

    def delete(self, layer: str, key: str) -> bool:
        return True

    def clear(self) -> None:
        pass

    def get_stats(self) -> dict[str, Any]:
        return dict(self._stats)


class InMemoryAnalysisCache(AnalysisCache):
    """Ephemeral in-memory cache implementation useful for testing and isolated runs."""

    def __init__(self):
        self._store: dict[tuple[str, str], tuple[Any, dict[str, Any]]] = {}
        self._hits = 0
        self._misses = 0

    def get(self, layer: str, key: str) -> Optional[Any]:
        cache_key = (layer, key)
        if cache_key in self._store:
            self._hits += 1
            return self._store[cache_key][0]
        self._misses += 1
        return None

    def set(self, layer: str, key: str, value: Any, metadata: Optional[dict[str, Any]] = None) -> bool:
        self._store[(layer, key)] = (value, metadata or {})
        return True

    def has(self, layer: str, key: str) -> bool:
        return (layer, key) in self._store

    def delete(self, layer: str, key: str) -> bool:
        return bool(self._store.pop((layer, key), None))

    def clear(self) -> None:
        self._store.clear()

    def get_stats(self) -> dict[str, Any]:
        return {
            "hits": self._hits,
            "misses": self._misses,
            "entries": len(self._store),
            "size_bytes": 0,
        }


class DiskAnalysisCache(AnalysisCache):
    """Persistent on-disk layered analysis cache with atomic writes and corruption recovery."""

    def __init__(
        self,
        cache_root: Optional[Path | str] = None,
        repo_namespace_id: Optional[str] = None,
        max_cache_size_bytes: int = 524288000,  # 500 MB default
        max_entries: int = 50000,
        enable_compression: bool = False,
        cache_dir: Optional[Path | str] = None,
    ):
        root = cache_dir if cache_dir is not None else cache_root
        if root is None:
            raise ValueError("cache_root or cache_dir must be specified")
        self.cache_root = Path(root).resolve()
        if repo_namespace_id is None:
            from analyzer.incremental.keys import compute_repo_namespace_id
            self.repo_namespace_id = compute_repo_namespace_id(self.cache_root)
        else:
            self.repo_namespace_id = repo_namespace_id
        self.max_cache_size_bytes = max_cache_size_bytes
        self.max_entries = max_entries
        self.enable_compression = enable_compression
        self._hits = 0
        self._misses = 0

        self.namespace_dir = self.cache_root / "v1" / self.repo_namespace_id
        self.namespace_dir.mkdir(parents=True, exist_ok=True)

    def _layer_dir(self, layer: str) -> Path:
        d = self.namespace_dir / layer.lower()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _artifact_path(self, layer: str, key: str) -> Path:
        ext = ".json.gz" if self.enable_compression or layer == "L2" else ".json"
        safe_key = key
        if any(c in key for c in ':*?"<>|/\\'):
            safe_key = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._layer_dir(layer) / f"{safe_key}{ext}"

    def get(self, layer: str, key: str) -> Optional[Any]:
        target_path = self._artifact_path(layer, key)
        if not target_path.is_file():
            self._misses += 1
            return None

        try:
            if target_path.suffix == ".gz":
                raw_bytes = gzip.decompress(target_path.read_bytes())
            else:
                raw_bytes = target_path.read_bytes()

            # Verify checksum before deserializing
            envelope = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError("Cache envelope is not a valid JSON object")

            if envelope.get("schema_version") != CACHE_ENVELOPE_SCHEMA_VERSION:
                logger.warning("Cache schema mismatch for key %s; forcing recomputation", key)
                self.delete(layer, key)
                self._misses += 1
                return None

            payload_raw = envelope.get("payload")
            expected_checksum = envelope.get("checksum")
            actual_checksum = hashlib.sha256(
                json.dumps(payload_raw, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            ).hexdigest()

            if expected_checksum != actual_checksum:
                logger.warning("Cache checksum failure for key %s; entry corrupted", key)
                self.delete(layer, key)
                self._misses += 1
                return None

            self._hits += 1
            # Update access timestamp for LRU
            try:
                target_path.touch(exist_ok=True)
            except OSError:
                pass
            return payload_raw

        except Exception as err:
            logger.warning("Failed to read cache artifact %s: %s. Treating as cache miss.", target_path, err)
            self.delete(layer, key)
            self._misses += 1
            return None

    def set(self, layer: str, key: str, value: Any, metadata: Optional[dict[str, Any]] = None) -> bool:
        target_path = self._artifact_path(layer, key)
        target_dir = target_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)

        payload_bytes = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        checksum = hashlib.sha256(payload_bytes).hexdigest()

        envelope = {
            "schema_version": CACHE_ENVELOPE_SCHEMA_VERSION,
            "key": key,
            "layer": layer,
            "checksum": checksum,
            "created_at": time.time(),
            "metadata": metadata or {},
            "payload": value,
        }

        serialized = json.dumps(envelope, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        if target_path.suffix == ".gz":
            final_bytes = gzip.compress(serialized)
        else:
            final_bytes = serialized

        # Atomic write protocol: write to unique temporary file then os.replace
        tmp_id = f"{key}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        tmp_path = target_dir / tmp_id

        try:
            tmp_path.write_bytes(final_bytes)
            # Atomic rename/replace
            os.replace(tmp_path, target_path)
            self._evict_if_needed()
            return True
        except Exception as err:
            logger.error("Failed to write atomic cache entry %s: %s", target_path, err)
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            return False

    def has(self, layer: str, key: str) -> bool:
        return self._artifact_path(layer, key).is_file()

    def delete(self, layer: str, key: str) -> bool:
        target_path = self._artifact_path(layer, key)
        if target_path.is_file():
            try:
                target_path.unlink()
                return True
            except OSError:
                return False
        return False

    def clear(self) -> None:
        target = self.cache_root if self.cache_root.is_dir() else self.namespace_dir
        if target.is_dir():
            for root, dirs, files in os.walk(target, topdown=False):
                for f in files:
                    try:
                        (Path(root) / f).unlink()
                    except OSError:
                        pass
                for d in dirs:
                    try:
                        (Path(root) / d).rmdir()
                    except OSError:
                        pass

    def _evict_if_needed(self) -> None:
        """Evict oldest accessed cache entries if size or entry bounds are exceeded."""
        try:
            entries: list[tuple[Path, int, float]] = []  # path, size, mtime
            total_size = 0

            for root, _, files in os.walk(self.namespace_dir):
                for f in files:
                    if f.endswith((".json", ".json.gz")) and not ".tmp." in f:
                        p = Path(root) / f
                        try:
                            st = p.stat()
                            entries.append((p, st.st_size, st.st_mtime))
                            total_size += st.st_size
                        except OSError:
                            pass

            if total_size <= self.max_cache_size_bytes and len(entries) <= self.max_entries:
                return

            # Sort by mtime ascending (oldest first)
            entries.sort(key=lambda e: e[2])

            remaining_count = len(entries)
            for p, size, _ in entries:
                if total_size <= self.max_cache_size_bytes and remaining_count <= self.max_entries:
                    break
                try:
                    p.unlink()
                    total_size -= size
                    remaining_count -= 1
                except OSError:
                    pass
        except Exception as err:
            logger.debug("Cache eviction encountered non-fatal error: %s", err)

    def get_stats(self) -> dict[str, Any]:
        total_size = 0
        total_entries = 0
        if self.namespace_dir.is_dir():
            for root, _, files in os.walk(self.namespace_dir):
                for f in files:
                    if f.endswith((".json", ".json.gz")) and not ".tmp." in f:
                        total_entries += 1
                        try:
                            total_size += (Path(root) / f).stat().st_size
                        except OSError:
                            pass

        return {
            "hits": self._hits,
            "misses": self._misses,
            "entries": total_entries,
            "size_bytes": total_size,
        }
