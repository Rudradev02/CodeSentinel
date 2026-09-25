"""Celery background worker task for repository static analysis."""

from datetime import datetime, timezone
import logging
from typing import Optional

from sqlalchemy.exc import OperationalError

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.errors import AnalysisCancelledError
from backend.app.db.sync_session import get_sync_db
from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.services.cache import AnalysisCacheService
from backend.app.services.persistence import PersistenceService
from backend.app.services.progress import ProgressPublisher
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="backend.app.workers.tasks.run_analysis_task",
    autoretry_for=(OperationalError,),
    max_retries=3,
    retry_backoff=True,
)
def run_analysis_task(self, job_id: str) -> dict:
    """Execute repository analysis in background worker.
    
    Receives job_id primarily; loads repository details and configuration from database
    using a synchronous database session. Emits real-time progress via Redis Pub/Sub,
    supports cooperative cancellation, and atomically persists the resulting snapshot.
    """
    logger.info("Worker picked up analysis job: %s (task_id: %s)", job_id, self.request.id)

    # 1. Fetch Job and Repository from Database
    with get_sync_db() as db:
        job = db.query(AnalysisJob).filter_by(id=job_id).first()
        if not job:
            logger.error("AnalysisJob %s not found in database", job_id)
            return {"job_id": job_id, "status": "NOT_FOUND"}

        # Store Celery task ID on the job record if not already set
        if not job.celery_task_id:
            job.celery_task_id = self.request.id
            db.commit()

        # Check if already cancelled
        if ProgressPublisher.is_cancelled(job_id) or job.status == "CANCELLED":
            logger.info("Job %s was cancelled before worker started", job_id)
            job.status = "CANCELLED"
            job.completed_at = datetime.now(timezone.utc)
            job.progress_message = "Analysis cancelled before execution"
            db.commit()
            ProgressPublisher.publish_progress(
                job_id, "CANCELLED", job.progress_percent, "CANCELLED", "Analysis cancelled before execution"
            )
            return {"job_id": job_id, "status": "CANCELLED"}

        repository = db.query(Repository).filter_by(id=job.repository_id).first()
        if not repository:
            logger.error("Repository %s not found for job %s", job.repository_id, job_id)
            job.status = "FAILED"
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = f"Repository {job.repository_id} not found"
            db.commit()
            ProgressPublisher.publish_progress(
                job_id, "FAILED", 0, "FAILED", error_message=f"Repository {job.repository_id} not found"
            )
            return {"job_id": job_id, "status": "FAILED"}

        repo_id = repository.id
        repo_path = repository.path
        repo_name = repository.name
        config_dict = job.configuration

        # Mark job as RUNNING
        job.status = "RUNNING"
        job.started_at = datetime.now(timezone.utc)
        job.progress_percent = 5
        job.progress_stage = "INITIALIZING"
        job.progress_message = "Initializing analysis pipeline..."
        db.commit()

    ProgressPublisher.publish_progress(
        job_id, "RUNNING", 5, "INITIALIZING", "Initializing analysis pipeline..."
    )

    # 2. Setup Progress and Cancellation Callbacks
    def on_progress(stage: str, percent: int, message: str) -> None:
        ProgressPublisher.publish_progress(job_id, "RUNNING", percent, stage, message)
        try:
            with get_sync_db() as db_inner:
                j = db_inner.query(AnalysisJob).filter_by(id=job_id).first()
                if j and j.status == "RUNNING":
                    j.progress_percent = percent
                    j.progress_stage = stage
                    j.progress_message = message
                    db_inner.commit()
        except Exception as exc:
            logger.debug("Minor failure updating DB progress for %s: %s", job_id, exc)

    def is_cancelled() -> bool:
        return ProgressPublisher.is_cancelled(job_id)

    # 3. Instantiate Pipeline & Run Analysis
    try:
        analysis_config: Optional[AnalysisConfig] = None
        if config_dict and isinstance(config_dict, dict):
            try:
                analysis_config = AnalysisConfig(**config_dict)
            except Exception as parse_err:
                logger.warning("Could not parse AnalysisConfig from job dict: %s", parse_err)

        mode = config_dict.get("mode", "full") if config_dict and isinstance(config_dict, dict) else "full"
        pipeline = AnalysisPipeline(analysis_config=analysis_config)
        result = pipeline.run(
            target_path=repo_path,
            repository_name=repo_name,
            analysis_config=analysis_config,
            on_progress=on_progress,
            is_cancelled=is_cancelled,
            mode=mode,
        )

        # 4. Atomic Persistence & Cache Storage
        with get_sync_db() as db_sync:
            snapshot = PersistenceService.save_analysis_snapshot_sync(
                db=db_sync,
                repository_id=repo_id,
                result=result,
                config_dict=config_dict,
            )

            # Store in cache
            if result.repository and result.repository.commit_hash:
                AnalysisCacheService.set_cached_snapshot_id(
                    repo_id, result.repository.commit_hash, snapshot.id
                )

            # Mark job COMPLETED
            job_record = db_sync.query(AnalysisJob).filter_by(id=job_id).first()
            if job_record:
                job_record.status = "COMPLETED"
                job_record.snapshot_id = snapshot.id
                job_record.completed_at = datetime.now(timezone.utc)
                job_record.progress_percent = 100
                job_record.progress_stage = "COMPLETED"
                job_record.progress_message = "Analysis completed successfully"
                db_sync.commit()

        ProgressPublisher.publish_progress(
            job_id,
            "COMPLETED",
            100,
            "COMPLETED",
            "Analysis completed successfully",
            snapshot_id=snapshot.id,
        )
        ProgressPublisher.clear_cancellation(job_id)
        logger.info("Analysis job %s completed successfully (snapshot: %s)", job_id, snapshot.id)
        return {"job_id": job_id, "status": "COMPLETED", "snapshot_id": snapshot.id}

    except AnalysisCancelledError:
        logger.info("Analysis job %s was cooperatively cancelled", job_id)
        with get_sync_db() as db_cancel:
            j = db_cancel.query(AnalysisJob).filter_by(id=job_id).first()
            if j:
                j.status = "CANCELLED"
                j.completed_at = datetime.now(timezone.utc)
                j.progress_stage = "CANCELLED"
                j.progress_message = "Analysis was cancelled by user"
                db_cancel.commit()

        ProgressPublisher.publish_progress(
            job_id, "CANCELLED", 0, "CANCELLED", "Analysis was cancelled by user"
        )
        ProgressPublisher.clear_cancellation(job_id)
        return {"job_id": job_id, "status": "CANCELLED"}

    except Exception as exc:
        logger.exception("Analysis job %s failed with error: %s", job_id, exc)
        with get_sync_db() as db_err:
            j = db_err.query(AnalysisJob).filter_by(id=job_id).first()
            if j:
                j.status = "FAILED"
                j.completed_at = datetime.now(timezone.utc)
                j.progress_stage = "FAILED"
                j.error_message = str(exc)
                db_err.commit()

        ProgressPublisher.publish_progress(
            job_id, "FAILED", 0, "FAILED", error_message=str(exc)
        )
        ProgressPublisher.clear_cancellation(job_id)
        return {"job_id": job_id, "status": "FAILED", "error": str(exc)}
