"""Service layer for analysis job lifecycle management and worker dispatch."""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.schemas.job import AnalysisJobDTO
from backend.app.services.progress import ProgressPublisher
from backend.app.workers.celery_app import celery_app
from backend.app.workers.tasks import run_analysis_task

logger = logging.getLogger(__name__)


class JobService:
    """Orchestrates job persistence, idempotent worker dispatch, and cooperative cancellation."""

    @staticmethod
    def to_dto(job: AnalysisJob) -> AnalysisJobDTO:
        """Convert an AnalysisJob ORM entity to a public AnalysisJobDTO."""
        return AnalysisJobDTO(
            id=job.id,
            repository_id=job.repository_id,
            status=job.status,
            snapshot_id=job.snapshot_id,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            progress_percent=job.progress_percent,
            progress_stage=job.progress_stage,
            progress_message=job.progress_message,
            error_message=job.error_message,
            stream_url=f"/api/v1/jobs/{job.id}/stream",
            configuration=job.configuration,
        )

    @staticmethod
    async def create_and_dispatch_job(
        db: AsyncSession,
        repository_id: str,
        config: Optional[dict[str, Any]] = None,
    ) -> AnalysisJobDTO:
        """Atomically create an analysis job, commit to DB, and dispatch to Celery worker.
        
        Guarantees idempotency (returns existing active job if RUNNING/QUEUED) and
        eliminates dispatch races by committing the database row BEFORE dispatch.
        """
        # 1. Validate parent repository exists
        repo_query = select(Repository).where(Repository.id == repository_id)
        repo_result = await db.execute(repo_query)
        repository = repo_result.scalar_one_or_none()
        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Repository with ID '{repository_id}' does not exist.",
            )

        # 2. Idempotency guard: check for existing active job
        active_query = select(AnalysisJob).where(
            AnalysisJob.repository_id == repository_id,
            AnalysisJob.status.in_(["QUEUED", "RUNNING"]),
        ).order_by(AnalysisJob.created_at.desc())
        active_result = await db.execute(active_query)
        existing_active = active_result.scalar_one_or_none()
        if existing_active:
            logger.info("Found existing active analysis job %s for repo %s", existing_active.id, repository_id)
            return JobService.to_dto(existing_active)

        # 3. Create new Job record
        job_id = str(uuid.uuid4())
        job = AnalysisJob(
            id=job_id,
            repository_id=repository_id,
            status="QUEUED",
            progress_percent=0,
            progress_stage="QUEUED",
            progress_message="Job queued for execution",
            created_at=datetime.now(timezone.utc),
            configuration=config,
        )
        db.add(job)

        # 4. Commit BEFORE dispatching to prevent worker race condition
        await db.commit()
        await db.refresh(job)

        # 5. Dispatch task to Celery
        try:
            task = run_analysis_task.delay(str(job.id))
            job.celery_task_id = task.id
            await db.commit()
            await db.refresh(job)
            logger.info("Dispatched analysis job %s to Celery (task_id: %s)", job.id, task.id)
        except Exception as exc:
            logger.exception("Failed to dispatch Celery worker task for job %s: %s", job.id, exc)
            job.status = "FAILED"
            job.error_message = f"Failed to dispatch worker task: {exc}"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Analysis worker task broker unavailable: {exc}",
            )

        return JobService.to_dto(job)

    @staticmethod
    async def get_job(db: AsyncSession, job_id: str) -> Optional[AnalysisJob]:
        """Fetch an AnalysisJob by ID."""
        query = select(AnalysisJob).where(AnalysisJob.id == job_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_jobs(
        db: AsyncSession,
        repository_id: str,
        skip: int = 0,
        limit: int = 20,
    ) -> tuple[list[AnalysisJob], int]:
        """Fetch paginated list of analysis jobs for a repository."""
        count_query = select(func.count(AnalysisJob.id)).where(AnalysisJob.repository_id == repository_id)
        total = (await db.execute(count_query)).scalar_one() or 0

        query = (
            select(AnalysisJob)
            .where(AnalysisJob.repository_id == repository_id)
            .order_by(AnalysisJob.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        items = list((await db.execute(query)).scalars().all())
        return items, total

    @staticmethod
    async def cancel_job(db: AsyncSession, job_id: str) -> AnalysisJobDTO:
        """Cooperatively cancel a running or queued analysis job."""
        job = await JobService.get_job(db, job_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis job with ID '{job_id}' not found.",
            )

        # If already terminal, return existing state
        if job.status in ("COMPLETED", "FAILED", "CANCELLED"):
            return JobService.to_dto(job)

        # 1. Set cooperative cancellation flag in Redis
        ProgressPublisher.request_cancellation(job_id)

        # 2. If job is still QUEUED, immediately update status in DB
        if job.status == "QUEUED":
            job.status = "CANCELLED"
            job.completed_at = datetime.now(timezone.utc)
            job.progress_stage = "CANCELLED"
            job.progress_message = "Analysis cancelled by user before execution"
            await db.commit()
            await db.refresh(job)

        # 3. Revoke task in Celery (terminate=False: cooperative)
        if job.celery_task_id:
            try:
                celery_app.control.revoke(job.celery_task_id, terminate=False)
            except Exception as exc:
                logger.warning("Failed to revoke Celery task %s: %s", job.celery_task_id, exc)

        return JobService.to_dto(job)
