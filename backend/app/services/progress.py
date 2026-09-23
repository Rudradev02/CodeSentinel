"""Redis Pub/Sub progress publisher and cooperative cancellation management."""

import json
import logging
from typing import Any, Optional
import redis

from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Obtain or initialize the synchronous Redis client singleton."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


class ProgressPublisher:
    """Manages publishing real-time job progress and cooperative cancellation flags."""

    @staticmethod
    def get_channel_name(job_id: str) -> str:
        """Derive the Redis Pub/Sub channel name for a job."""
        return f"codesentinel:job:{job_id}"

    @staticmethod
    def get_cancel_key(job_id: str) -> str:
        """Derive the Redis key used for cooperative cancellation flags."""
        return f"codesentinel:cancel:{job_id}"

    @classmethod
    def publish_progress(
        cls,
        job_id: str,
        status: str,
        progress_percent: int,
        stage: Optional[str] = None,
        message: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Publish a structured progress event to the job's Redis Pub/Sub channel."""
        channel = cls.get_channel_name(job_id)
        payload: dict[str, Any] = {
            "job_id": job_id,
            "status": status,
            "progress_percent": progress_percent,
            "progress_stage": stage,
            "progress_message": message,
            "snapshot_id": snapshot_id,
            "error_message": error_message,
        }
        try:
            client = get_redis_client()
            client.publish(channel, json.dumps(payload))
        except Exception as exc:
            logger.warning("Failed to publish progress event to Redis for job %s: %s", job_id, exc)

    @classmethod
    def request_cancellation(cls, job_id: str) -> None:
        """Set a cooperative cancellation flag in Redis with a 1-hour TTL."""
        key = cls.get_cancel_key(job_id)
        try:
            client = get_redis_client()
            client.set(key, "1", ex=3600)
        except Exception as exc:
            logger.warning("Failed to set cancellation flag in Redis for job %s: %s", job_id, exc)

    @classmethod
    def is_cancelled(cls, job_id: str) -> bool:
        """Check whether a cooperative cancellation flag has been set for this job."""
        key = cls.get_cancel_key(job_id)
        try:
            client = get_redis_client()
            val = client.get(key)
            return val == "1"
        except Exception as exc:
            logger.warning("Failed to check cancellation flag in Redis for job %s: %s", job_id, exc)
            return False

    @classmethod
    def clear_cancellation(cls, job_id: str) -> None:
        """Remove cancellation flag upon cleanup."""
        key = cls.get_cancel_key(job_id)
        try:
            client = get_redis_client()
            client.delete(key)
        except Exception:
            pass
