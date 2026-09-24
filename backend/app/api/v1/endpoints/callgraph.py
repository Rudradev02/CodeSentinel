"""Phase 15 Call Graph Summary API endpoint."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.logging import get_logger
from backend.app.db.session import get_db
from backend.app.schemas.callgraph import CallGraphSummaryDTO
from backend.app.services.persistence import PersistenceService
from backend.app.services.repository_store import RepositoryStore

logger = get_logger("codesentinel.api.callgraph")

router = APIRouter()


@router.get(
    "/{repository_id}/analyses/{analysis_id}/callgraph",
    response_model=CallGraphSummaryDTO,
    summary="Get Call Graph Summary for an analysis snapshot",
    description="Retrieve aggregate static call graph statistics, resolution rates, and interprocedural finding counts for a historical snapshot.",
)
async def get_callgraph_summary(
    repository_id: str,
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> CallGraphSummaryDTO:
    """Fetch call graph summary metrics enforcing repository boundary isolation."""
    repo = await RepositoryStore.get_repository(db, repository_id)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )

    snapshot = await PersistenceService.get_analysis_snapshot(
        db=db,
        repository_id=repository_id,
        analysis_id=analysis_id,
    )
    if snapshot is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis snapshot '{analysis_id}' for repository '{repository_id}' was not found.",
        )

    if not snapshot.call_graph_summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No call graph data available for analysis snapshot '{analysis_id}'.",
        )

    summary_data = dict(snapshot.call_graph_summary)
    summary_data["analysis_id"] = snapshot.id
    return CallGraphSummaryDTO(**summary_data)
