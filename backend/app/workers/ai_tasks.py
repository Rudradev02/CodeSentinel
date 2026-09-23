"""Celery background worker tasks for Phase 12 AI Enrichment."""

import logging
from typing import Optional

from backend.app.db.sync_session import get_sync_db
from backend.app.services.ai.orchestrator import AIEnrichmentOrchestrator
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="backend.app.workers.ai_tasks.run_ai_enrichment_task",
    max_retries=2,
    default_retry_delay=5,
)
def run_ai_enrichment_task(
    self,
    finding_id: str,
    provider_name: Optional[str] = None,
    model_name: Optional[str] = None,
    force_refresh: bool = False,
) -> dict:
    """Execute finding enrichment and remediation synthesis in background worker."""
    logger.info("Worker picked up AI enrichment for finding: %s (task_id: %s)", finding_id, self.request.id)

    with get_sync_db() as db:
        try:
            record = AIEnrichmentOrchestrator.enrich_finding_sync(
                db=db,
                finding_id=finding_id,
                provider_name=provider_name,
                model_name=model_name,
                force_refresh=force_refresh,
            )
            return {
                "finding_id": finding_id,
                "enrichment_id": record.id,
                "status": record.status,
                "error": record.error_message,
            }
        except Exception as exc:
            logger.exception("Error executing run_ai_enrichment_task: %s", exc)
            return {
                "finding_id": finding_id,
                "status": "FAILED",
                "error": str(exc),
            }
