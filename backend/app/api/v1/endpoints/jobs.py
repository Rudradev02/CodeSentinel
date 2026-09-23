"""REST API endpoints for analysis jobs query, cancellation, and repository history."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.session import get_db
from backend.app.schemas.job import AnalysisJobDTO, JobListResponse
from backend.app.services.job_service import JobService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/jobs/{job_id}",
    response_model=AnalysisJobDTO,
    summary="Get analysis job status and progress",
    description="Retrieve execution state, progress percentage, current stage, and resulting snapshot ID.",
)
async def get_job_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisJobDTO:
    """Fetch status and metadata for a specific analysis job."""
    job = await JobService.get_job(db, job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found.",
        )
    return JobService.to_dto(job)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=AnalysisJobDTO,
    summary="Cancel a running or queued analysis job",
    description="Cooperatively request cancellation of an analysis job without killing worker threads.",
)
async def cancel_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisJobDTO:
    """Request cooperative cancellation of an in-progress or queued analysis job."""
    return await JobService.cancel_job(db, job_id)


@router.get(
    "/repositories/{repository_id}/jobs",
    response_model=JobListResponse,
    summary="List analysis jobs for a repository",
    description="Retrieve paginated list of analysis jobs for a given repository ordered by creation date descending.",
)
async def list_repository_jobs(
    repository_id: str,
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(20, ge=1, le=100, description="Page size limit"),
    db: AsyncSession = Depends(get_db),
) -> JobListResponse:
    """Fetch paginated list of historical jobs for a repository."""
    jobs, total = await JobService.list_jobs(db, repository_id, skip=skip, limit=limit)
    items = [JobService.to_dto(j) for j in jobs]
    return JobListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
    )
