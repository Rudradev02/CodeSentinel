"""Redis-based caching service for analysis snapshots."""

import logging
from typing import Optional
from backend.app.core.config import get_settings
from backend.app.services.progress import get_redis_client

logger = logging.getLogger(__name__)


class AnalysisCacheService:
    """Provides snapshot caching by repository ID and Git commit hash."""

    @staticmethod
    def _make_key(repository_id: str, commit_hash: str) -> str:
        return f"codesentinel:cache:analysis:{repository_id}:{commit_hash}"

    @classmethod
    def get_cached_snapshot_id(
        cls,
        repository_id: str,
        commit_hash: Optional[str],
    ) -> Optional[str]:
        """Retrieve a cached snapshot ID if available for this repository and commit hash.
        
        Returns None if commit_hash is missing, empty, or unknown, or if Redis is unreachable.
        """
        if not commit_hash or commit_hash.strip() in ("", "unknown"):
            return None

        key = cls._make_key(repository_id, commit_hash.strip())
        try:
            client = get_redis_client()
            val = client.get(key)
            if val:
                logger.info("Analysis cache hit for %s at commit %s -> snapshot %s", repository_id, commit_hash, val)
                return str(val)
        except Exception as exc:
            logger.warning("Cache lookup failed for %s: %s", key, exc)

        return None

    @classmethod
    def set_cached_snapshot_id(
        cls,
        repository_id: str,
        commit_hash: Optional[str],
        snapshot_id: str,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store a mapping from (repository_id, commit_hash) to snapshot_id in Redis."""
        if not commit_hash or commit_hash.strip() in ("", "unknown"):
            return

        key = cls._make_key(repository_id, commit_hash.strip())
        ttl = ttl_seconds or get_settings().CACHE_TTL_SECONDS
        try:
            client = get_redis_client()
            client.set(key, snapshot_id, ex=ttl)
            logger.info("Cached snapshot %s for repo %s at commit %s (TTL: %ds)", snapshot_id, repository_id, commit_hash, ttl)
        except Exception as exc:
            logger.warning("Failed to cache snapshot for %s: %s", key, exc)

    @classmethod
    def invalidate_repository(cls, repository_id: str) -> None:
        """Invalidate all cached snapshots for a given repository."""
        pattern = f"codesentinel:cache:analysis:{repository_id}:*"
        try:
            client = get_redis_client()
            keys = client.keys(pattern)
            if keys:
                client.delete(*keys)
                logger.info("Invalidated %d cache entries for repository %s", len(keys), repository_id)
        except Exception as exc:
            logger.warning("Failed to invalidate cache for repo %s: %s", repository_id, exc)
