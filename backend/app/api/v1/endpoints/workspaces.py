"""REST API endpoints for multi-repository Workspaces and composite snapshots (Phase 28)."""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from analyzer.workspace.dag import WorkspaceDAG
from analyzer.workspace.models import RepositoryMember, WorkspaceManifest
from backend.app.db.session import get_db
from backend.app.db.sync_session import get_sync_db
from backend.app.models.organization import Organization
from backend.app.models.repository import Repository
from backend.app.models.workspace import Workspace, WorkspaceRepository, WorkspaceSnapshot
from backend.app.schemas.workspace import (
    WorkspaceCreateDTO,
    WorkspaceDetailDTO,
    WorkspaceMemberDTO,
    WorkspaceResponseDTO,
    WorkspaceScanRequestDTO,
    WorkspaceScanResponseDTO,
    WorkspaceSnapshotDetailDTO,
    WorkspaceSnapshotSummaryDTO,
)
from backend.app.workers.tasks import run_workspace_scan_task

router = APIRouter()


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[-\s]+", "-", cleaned)


@router.post(
    "/organizations/{organization_id}/workspaces",
    response_model=WorkspaceResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Create Workspace in Organization",
)
async def create_workspace(
    organization_id: str,
    payload: WorkspaceCreateDTO,
    db: AsyncSession = Depends(get_db),
) -> WorkspaceResponseDTO:
    """Create a new multi-repository workspace under an organization."""
    org_res = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")

    slug = payload.slug or _slugify(payload.name)
    existing = await db.execute(
        select(Workspace).where(Workspace.organization_id == organization_id, Workspace.slug == slug)
    )
    if existing.scalar_one_or_none():
        slug = f"{slug}-{uuid.uuid4().hex[:6]}"

    ws = Workspace(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        name=payload.name,
        slug=slug,
        manifest_path=payload.manifest_path,
        config_payload=payload.config_payload,
    )
    db.add(ws)
    await db.flush()

    for member in payload.repositories:
        link = WorkspaceRepository(
            workspace_id=ws.id,
            repository_id=member.repository_id,
            role=member.role,
            criticality=member.criticality,
            depends_on=member.depends_on,
        )
        db.add(link)

    await db.commit()
    await db.refresh(ws)
    return WorkspaceResponseDTO.model_validate(ws)


@router.get(
    "/workspaces/{workspace_id}",
    response_model=WorkspaceDetailDTO,
    summary="Get Workspace Details & Topology",
)
async def get_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
) -> WorkspaceDetailDTO:
    """Fetch workspace details, member topology, and compute DAG execution waves."""
    ws_res = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = ws_res.scalar_one_or_none()
    if not ws:
        raise HTTPException(status_code=404, detail=f"Workspace {workspace_id} not found")

    links_res = await db.execute(select(WorkspaceRepository).where(WorkspaceRepository.workspace_id == workspace_id))
    links = links_res.scalars().all()

    members_dto = [
        WorkspaceMemberDTO(
            repository_id=link.repository_id,
            role=link.role,
            criticality=link.criticality,
            depends_on=link.depends_on or [],
        )
        for link in links
    ]

    # Compute execution waves
    waves: list[list[str]] = []
    try:
        manifest_members = [
            RepositoryMember(
                id=m.repository_id,
                path=f"./{m.repository_id}",
                role=m.role,
                criticality=m.criticality,
                depends_on=m.depends_on,
            )
            for m in members_dto
        ]
        manifest = WorkspaceManifest(
            version="1.0",
            workspace_id=ws.slug,
            name=ws.name,
            organization_id=ws.organization_id,
            repositories=manifest_members,
        )
        dag = WorkspaceDAG(manifest)
        waves = dag.get_execution_waves()
    except Exception:
        waves = [[m.repository_id for m in members_dto]] if members_dto else []

    # Get latest snapshot info
    snap_res = await db.execute(
        select(WorkspaceSnapshot)
        .where(WorkspaceSnapshot.workspace_id == workspace_id)
        .order_by(WorkspaceSnapshot.created_at.desc())
        .limit(1)
    )
    latest_snap = snap_res.scalar_one_or_none()

    return WorkspaceDetailDTO(
        id=ws.id,
        organization_id=ws.organization_id,
        name=ws.name,
        slug=ws.slug,
        manifest_path=ws.manifest_path,
        config_payload=ws.config_payload,
        created_at=ws.created_at,
        updated_at=ws.updated_at,
        repositories=members_dto,
        execution_waves=waves,
        latest_snapshot_id=latest_snap.id if latest_snap else None,
        composite_health_score=latest_snap.composite_health_score if latest_snap else None,
        composite_grade=latest_snap.composite_grade if latest_snap else None,
    )


@router.post(
    "/workspaces/{workspace_id}/scan",
    response_model=WorkspaceScanResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger Workspace Scan",
)
async def trigger_workspace_scan(
    workspace_id: str,
    payload: Optional[WorkspaceScanRequestDTO] = None,
    db: AsyncSession = Depends(get_db),
) -> WorkspaceScanResponseDTO:
    """Enqueue an asynchronous multi-repository workspace analysis run."""
    ws_res = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = ws_res.scalar_one_or_none()
    if not ws:
        raise HTTPException(status_code=404, detail=f"Workspace {workspace_id} not found")

    manifest_path = payload.manifest_path if payload else None

    # Enqueue Celery task or run async fallback
    try:
        task = run_workspace_scan_task.delay(workspace_id=workspace_id, manifest_path=manifest_path)
        task_id = task.id
    except Exception:
        # Broker offline fallback (e.g. running in direct threadpool or synchronous mode)
        task_id = f"local-{uuid.uuid4().hex[:8]}"
        def _run_local():
            run_workspace_scan_task(workspace_id=workspace_id, manifest_path=manifest_path)
        run_in_threadpool(_run_local)

    return WorkspaceScanResponseDTO(
        workspace_id=workspace_id,
        task_id=task_id,
        status="ACCEPTED",
        message="Workspace analysis task successfully enqueued",
    )


@router.get(
    "/workspaces/{workspace_id}/snapshots",
    response_model=list[WorkspaceSnapshotSummaryDTO],
    summary="List Workspace Snapshots",
)
async def list_workspace_snapshots(
    workspace_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceSnapshotSummaryDTO]:
    """Fetch historical analysis snapshots for a workspace."""
    query = (
        select(WorkspaceSnapshot)
        .where(WorkspaceSnapshot.workspace_id == workspace_id)
        .order_by(WorkspaceSnapshot.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    snaps = result.scalars().all()
    return [WorkspaceSnapshotSummaryDTO.model_validate(s) for s in snaps]


@router.get(
    "/workspaces/{workspace_id}/snapshots/{snapshot_id}",
    response_model=WorkspaceSnapshotDetailDTO,
    summary="Get Workspace Snapshot Details",
)
async def get_workspace_snapshot(
    workspace_id: str,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
) -> WorkspaceSnapshotDetailDTO:
    """Get full details of a composite workspace snapshot including DSSE attestation."""
    query = select(WorkspaceSnapshot).where(
        WorkspaceSnapshot.id == snapshot_id,
        WorkspaceSnapshot.workspace_id == workspace_id,
    )
    result = await db.execute(query)
    snap = result.scalar_one_or_none()
    if not snap:
        raise HTTPException(
            status_code=404,
            detail=f"WorkspaceSnapshot {snapshot_id} not found for workspace {workspace_id}",
        )
    return WorkspaceSnapshotDetailDTO.model_validate(snap)
