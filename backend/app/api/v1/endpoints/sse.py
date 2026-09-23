"""Server-Sent Events (SSE) progress streaming endpoint for analysis jobs."""

import asyncio
from collections.abc import AsyncGenerator
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from backend.app.core.config import get_settings
from backend.app.db.session import get_db
from backend.app.services.job_service import JobService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/jobs/{job_id}/stream",
    summary="Stream real-time analysis job progress via Server-Sent Events (SSE)",
    response_description="Server-Sent Events stream yielding progress, completed, failed, or cancelled events",
)
async def stream_job_progress(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> EventSourceResponse:
    """Stream live progress updates for an AnalysisJob.
    
    Architecture:
    1. Immediately emits current job status from PostgreSQL.
    2. If the job is already terminal (COMPLETED, FAILED, CANCELLED), terminates immediately.
    3. If active, subscribes to Redis Pub/Sub channel for live worker progress events.
    4. Automatically cleans up Redis subscription on terminal state or client disconnect.
    """
    job = await JobService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found.",
        )

    # Capture initial DB state
    initial_status = job.status
    initial_event_name = "progress"
    if initial_status == "COMPLETED":
        initial_event_name = "completed"
    elif initial_status == "FAILED":
        initial_event_name = "failed"
    elif initial_status == "CANCELLED":
        initial_event_name = "cancelled"

    initial_payload = {
        "job_id": job.id,
        "status": job.status,
        "progress_percent": job.progress_percent,
        "progress_stage": job.progress_stage,
        "progress_message": job.progress_message,
        "snapshot_id": job.snapshot_id,
        "error_message": job.error_message,
    }

    async def event_generator() -> AsyncGenerator[dict[str, Any], None]:
        # 1. Yield initial state from PostgreSQL
        yield {
            "event": initial_event_name,
            "data": json.dumps(initial_payload),
        }

        # If already terminal, close stream immediately
        if initial_status in ("COMPLETED", "FAILED", "CANCELLED"):
            return

        # 2. Subscribe to Redis Pub/Sub for live events
        settings = get_settings()
        channel_name = f"codesentinel:job:{job_id}"
        redis_client: Optional[aioredis.Redis] = None
        pubsub = None

        try:
            redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = redis_client.pubsub()
            await pubsub.subscribe(channel_name)

            while True:
                if await request.is_disconnected():
                    logger.debug("Client disconnected from SSE stream for job %s", job_id)
                    break

                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    raw_data = message.get("data", "{}")
                    event_type = "progress"
                    try:
                        payload = json.loads(raw_data)
                        msg_status = payload.get("status")
                        if msg_status == "COMPLETED":
                            event_type = "completed"
                        elif msg_status == "FAILED":
                            event_type = "failed"
                        elif msg_status == "CANCELLED":
                            event_type = "cancelled"

                        yield {
                            "event": event_type,
                            "data": raw_data,
                        }

                        if msg_status in ("COMPLETED", "FAILED", "CANCELLED"):
                            break
                    except json.JSONDecodeError:
                        yield {
                            "event": "progress",
                            "data": raw_data,
                        }
                else:
                    await asyncio.sleep(0.5)

        except Exception as exc:
            logger.warning("Error during SSE streaming for job %s: %s", job_id, exc)
        finally:
            if pubsub:
                try:
                    await pubsub.unsubscribe(channel_name)
                    await pubsub.close()
                except Exception:
                    pass
            if redis_client:
                try:
                    await redis_client.close()
                except Exception:
                    pass

    return EventSourceResponse(
        event_generator(),
        ping=get_settings().SSE_KEEPALIVE_SECONDS,
    )
