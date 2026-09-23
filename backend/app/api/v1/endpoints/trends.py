"""Longitudinal Trend API endpoint for CodeSentinel."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.logging import get_logger
from backend.app.db.session import get_db
from backend.app.schemas.trend import LongitudinalTrendDTO
from backend.app.services.trend_service import TrendService

logger = get_logger("codesentinel.api.trends")

router = APIRouter()


@router.get(
    "/{repository_id}/trends",
    response_model=LongitudinalTrendDTO,
    summary="Get repository longitudinal trends and historical trajectories",
    description="Retrieve longitudinal quality trajectory, defect velocity, severity volume series, and component architectural drift.",
)
async def get_repository_trends(
    repository_id: str,
    branch: Optional[str] = Query(None, description="Filter trajectory to specific branch"),
    days: Optional[int] = Query(None, ge=1, description="Historical lookback window in days"),
    limit: int = Query(50, ge=1, le=200, description="Maximum snapshots to include in timeline (1-200)"),
    db: AsyncSession = Depends(get_db),
) -> LongitudinalTrendDTO:
    """Compute and return longitudinal quality intelligence for a repository."""
    try:
        return await TrendService.get_repository_trends(
            db=db,
            repository_id=repository_id,
            branch=branch,
            days=days,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except Exception as exc:
        logger.error("Error computing trends for repo %s: %s", repository_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute repository trends: {exc}",
        )
