"""Repository Catalog and Historical Analysis endpoints for CodeSentinel API."""

from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.results import AnalysisResult
from backend.app.core.exceptions import PathNotFoundException
from backend.app.core.logging import get_logger
from backend.app.core.security import validate_repository_path
from backend.app.db.session import get_db
from backend.app.schemas.analysis import AnalysisResultDTO
from backend.app.schemas.repository import (
    AnalysisHistoryResponse,
    AnalysisSnapshotSummaryDTO,
    RepositoryCreateRequest,
    RepositoryListResponse,
    RepositoryResponse,
    RunAnalysisRequest,
)
from backend.app.services.persistence import PersistenceService
from backend.app.services.repository_store import RepositoryStore

logger = get_logger("codesentinel.api.repositories")

router = APIRouter()


@router.post(
    "",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a repository",
    description="Register a local codebase repository for tracking, snapshotting, and historical analysis.",
)
async def register_repository(
    request: RepositoryCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> RepositoryResponse:
    """Register a new repository with path security boundary enforcement."""
    repo, created = await RepositoryStore.register_repository(
        db=db,
        path_str=request.path,
        name=request.name,
    )
    logger.info("Repository registered: id=%s path=%s (created=%s)", repo.id, repo.path, created)
    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        path=repo.path,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        analysis_count=len(repo.analyses) if repo.analyses else 0,
    )


@router.get(
    "",
    response_model=RepositoryListResponse,
    summary="List registered repositories",
    description="Retrieve paginated list of all registered repositories.",
)
async def list_repositories(
    skip: int = Query(default=0, ge=0, description="Offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Page size limit"),
    db: AsyncSession = Depends(get_db),
) -> RepositoryListResponse:
    """List registered repositories."""
    repos, total = await RepositoryStore.list_repositories(db=db, skip=skip, limit=limit)
    items = [
        RepositoryResponse(
            id=r.id,
            name=r.name,
            path=r.path,
            created_at=r.created_at,
            updated_at=r.updated_at,
            analysis_count=len(r.analyses) if r.analyses else 0,
        )
        for r in repos
    ]
    return RepositoryListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Get repository details",
)
async def get_repository(
    repository_id: str,
    db: AsyncSession = Depends(get_db),
) -> RepositoryResponse:
    """Fetch details for a single registered repository."""
    repo = await RepositoryStore.get_repository(db, repository_id)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )
    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        path=repo.path,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        analysis_count=len(repo.analyses) if repo.analyses else 0,
    )


@router.delete(
    "/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unregister a repository",
)
async def delete_repository(
    repository_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a registered repository and cascade deletion of its historical analyses."""
    deleted = await RepositoryStore.delete_repository(db, repository_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )


@router.post(
    "/{repository_id}/analyses",
    response_model=AnalysisResultDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Run analysis and persist immutable snapshot",
    description="Executes synchronous static analysis on the registered repository and persists an immutable snapshot.",
)
async def run_and_persist_analysis(
    repository_id: str,
    request: Optional[RunAnalysisRequest] = None,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResultDTO:
    """Trigger static analysis and store an immutable historical snapshot."""
    repo = await RepositoryStore.get_repository(db, repository_id)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )

    # 1. Validate repository path exists on filesystem
    canonical_path = validate_repository_path(repo.path)

    # 2. Build analysis config
    config_kwargs = {}
    if request:
        if request.fail_on:
            config_kwargs["fail_on_severity"] = request.fail_on.upper()
        if request.enabled_rules:
            config_kwargs["enabled_rules"] = request.enabled_rules
        if request.disabled_rules:
            config_kwargs["disabled_rules"] = request.disabled_rules
        if request.max_component_depth:
            config_kwargs["max_component_depth"] = request.max_component_depth

    analysis_config = AnalysisConfig(**config_kwargs)

    # 3. Execute analysis pipeline synchronously in thread pool
    pipeline = AnalysisPipeline(analysis_config=analysis_config)
    result: AnalysisResult = await run_in_threadpool(
        pipeline.run,
        target_path=canonical_path,
        analysis_config=analysis_config,
    )

    # 4. Atomically persist snapshot into database
    config_payload = {
        "fail_on": request.fail_on if request else None,
        "enabled_rules": request.enabled_rules if request else None,
        "disabled_rules": request.disabled_rules if request else None,
        "max_component_depth": request.max_component_depth if request else 2,
    }
    snapshot = await PersistenceService.save_analysis_snapshot(
        db=db,
        repository_id=repo.id,
        result=result,
        config_dict=config_payload,
    )
    logger.info("Persisted immutable analysis snapshot %s for repo %s", snapshot.id, repo.id)

    # 5. Return reconstructed AnalysisResultDTO
    return PersistenceService.reconstruct_analysis_dto(
        snapshot=snapshot,
        repo_path=canonical_path,
        repo_name=repo.name,
    )


@router.post(
    "/{repository_id}/snapshots",
    response_model=AnalysisResultDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Directly persist an externally computed AnalysisResult",
    description="Synchronizes a completed AnalysisResult (e.g. from CLI --save) into the database as an immutable snapshot.",
)
async def persist_external_snapshot(
    repository_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResultDTO:
    """Persist an externally produced AnalysisResult as an immutable historical record."""
    repo = await RepositoryStore.get_repository(db, repository_id)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )

    try:
        result = AnalysisResult(**payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid AnalysisResult payload: {exc}",
        )

    snapshot = await PersistenceService.save_analysis_snapshot(
        db=db,
        repository_id=repo.id,
        result=result,
        config_dict=None,
    )
    logger.info("Directly synchronized snapshot %s for repository %s", snapshot.id, repo.id)

    return PersistenceService.reconstruct_analysis_dto(
        snapshot=snapshot,
        repo_path=Path(repo.path),
        repo_name=repo.name,
    )


@router.get(
    "/{repository_id}/analyses",
    response_model=AnalysisHistoryResponse,
    summary="List historical analysis snapshots",
    description="Retrieve paginated timeline of immutable historical analysis snapshots for this repository.",
)
async def list_repository_analyses(
    repository_id: str,
    skip: int = Query(default=0, ge=0, description="Offset"),
    limit: int = Query(default=20, ge=1, le=100, description="Page limit"),
    db: AsyncSession = Depends(get_db),
) -> AnalysisHistoryResponse:
    """List historical analysis snapshots for a registered repository."""
    repo = await RepositoryStore.get_repository(db, repository_id)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository with ID '{repository_id}' was not found.",
        )

    snapshots, total = await PersistenceService.list_analysis_snapshots(
        db=db,
        repository_id=repository_id,
        skip=skip,
        limit=limit,
    )

    items = [
        AnalysisSnapshotSummaryDTO(
            id=s.id,
            repository_id=s.repository_id,
            created_at=s.created_at,
            commit_hash=s.commit_hash,
            branch=s.branch,
            is_dirty=s.is_dirty,
            analyzer_version=s.analyzer_version,
            status=s.status,
            duration_seconds=s.duration_seconds,
            overall_score=s.overall_score,
            overall_grade=s.overall_grade,
            architecture_score=s.architecture_score,
            architecture_grade=s.architecture_grade,
            security_score=s.security_score,
            security_grade=s.security_grade,
            total_findings=s.total_findings,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            info_count=s.info_count,
        )
        for s in snapshots
    ]

    return AnalysisHistoryResponse(items=items, total=total, skip=skip, limit=limit)


@router.get(
    "/{repository_id}/analyses/{analysis_id}",
    response_model=AnalysisResultDTO,
    summary="Retrieve a historical analysis snapshot",
    description="Retrieve full canonical analysis snapshot reconstructed from persistent storage without re-running analyzer.",
)
async def get_historical_analysis(
    repository_id: str,
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResultDTO:
    """Fetch an immutable historical analysis snapshot enforcing repository boundary isolation."""
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

    return PersistenceService.reconstruct_analysis_dto(
        snapshot=snapshot,
        repo_path=Path(repo.path),
        repo_name=repo.name,
    )
