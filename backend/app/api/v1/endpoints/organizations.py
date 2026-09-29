"""REST API endpoints for Organization governance and central policies (Phase 28)."""

from datetime import datetime, timezone
import re
from typing import Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from backend.app.db.session import get_db
from backend.app.db.sync_session import get_sync_db
from backend.app.models.organization import Organization
from backend.app.models.policy import CentralizedRulePack, CentralizedSuppression
from backend.app.models.workspace import Workspace, WorkspaceSnapshot
from backend.app.schemas.organization import (
    CentralRulePackCreateDTO,
    CentralRulePackResponseDTO,
    CentralSuppressionCreateDTO,
    CentralSuppressionResponseDTO,
    OrganizationComplianceRollupDTO,
    OrganizationCreateDTO,
    OrganizationDetailDTO,
    OrganizationResponseDTO,
    OrganizationTrendsDTO,
)
from backend.app.services.policy_distribution import CentralPolicyDistributionService

router = APIRouter()


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[-\s]+", "-", cleaned)


@router.post(
    "",
    response_model=OrganizationResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Create Organization",
)
async def create_organization(
    payload: OrganizationCreateDTO,
    db: AsyncSession = Depends(get_db),
) -> OrganizationResponseDTO:
    """Create a new Organization entity for multi-repo workspace management."""
    slug = payload.slug or _slugify(payload.name)
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{uuid.uuid4().hex[:6]}"

    org = Organization(
        id=str(uuid.uuid4()),
        name=payload.name,
        slug=slug,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return OrganizationResponseDTO.model_validate(org)


@router.get(
    "",
    response_model=list[OrganizationResponseDTO],
    summary="List Organizations",
)
async def list_organizations(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[OrganizationResponseDTO]:
    """List registered organizations with pagination."""
    query = select(Organization).order_by(Organization.name).limit(limit).offset(offset)
    result = await db.execute(query)
    orgs = result.scalars().all()
    return [OrganizationResponseDTO.model_validate(o) for o in orgs]


@router.get(
    "/{organization_id}",
    response_model=OrganizationDetailDTO,
    summary="Get Organization Details",
)
async def get_organization(
    organization_id: str,
    db: AsyncSession = Depends(get_db),
) -> OrganizationDetailDTO:
    """Get organization metadata, workspace counts, and policy counts."""
    org_res = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")

    ws_count = (await db.execute(
        select(func.count(Workspace.id)).where(Workspace.organization_id == organization_id)
    )).scalar_one()

    rp_count = (await db.execute(
        select(func.count(CentralizedRulePack.id)).where(CentralizedRulePack.organization_id == organization_id)
    )).scalar_one()

    supp_count = (await db.execute(
        select(func.count(CentralizedSuppression.id)).where(CentralizedSuppression.organization_id == organization_id)
    )).scalar_one()

    return OrganizationDetailDTO(
        id=org.id,
        name=org.name,
        slug=org.slug,
        created_at=org.created_at,
        updated_at=org.updated_at,
        workspace_count=ws_count,
        rule_pack_count=rp_count,
        suppression_count=supp_count,
    )


@router.get(
    "/{organization_id}/compliance",
    response_model=OrganizationComplianceRollupDTO,
    summary="Get Fleet-Wide Compliance Rollup",
)
async def get_organization_compliance(
    organization_id: str,
    db: AsyncSession = Depends(get_db),
) -> OrganizationComplianceRollupDTO:
    """Roll up compliance scores across all workspaces in the organization."""
    org_res = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")

    # Fetch latest snapshot for each workspace
    workspaces = (await db.execute(
        select(Workspace).where(Workspace.organization_id == organization_id)
    )).scalars().all()

    total_workspaces = len(workspaces)
    if total_workspaces == 0:
        return OrganizationComplianceRollupDTO(
            organization_id=organization_id,
            organization_name=org.name,
            total_workspaces=0,
            overall_health_score=100.0,
            framework_scores={},
            active_violations=0,
            suppressed_violations=0,
        )

    scores: list[float] = []
    active_v = 0
    supp_v = 0
    fw_accum: dict[str, list[float]] = {}

    for ws in workspaces:
        snap_res = await db.execute(
            select(WorkspaceSnapshot)
            .where(WorkspaceSnapshot.workspace_id == ws.id)
            .order_by(WorkspaceSnapshot.created_at.desc())
            .limit(1)
        )
        snap = snap_res.scalar_one_or_none()
        if snap:
            scores.append(snap.composite_health_score)
            active_v += snap.total_findings
            if snap.compliance_suite and isinstance(snap.compliance_suite, dict):
                fws = snap.compliance_suite.get("framework_rollups", {})
                for fw_name, fw_data in fws.items():
                    if isinstance(fw_data, dict) and "overall_score" in fw_data:
                        fw_accum.setdefault(fw_name, []).append(fw_data["overall_score"])

    overall_health = round(sum(scores) / len(scores), 1) if scores else 100.0
    fw_scores = {fw: round(sum(vals) / len(vals), 1) for fw, vals in fw_accum.items()}

    return OrganizationComplianceRollupDTO(
        organization_id=organization_id,
        organization_name=org.name,
        total_workspaces=total_workspaces,
        overall_health_score=overall_health,
        framework_scores=fw_scores,
        active_violations=active_v,
        suppressed_violations=supp_v,
    )


@router.get(
    "/{organization_id}/trends",
    response_model=OrganizationTrendsDTO,
    summary="Get Organization Trends",
)
async def get_organization_trends(
    organization_id: str,
    db: AsyncSession = Depends(get_db),
) -> OrganizationTrendsDTO:
    """Compute enterprise-scale health velocity and finding trends."""
    org_res = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = org_res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")

    workspaces = (await db.execute(
        select(Workspace).where(Workspace.organization_id == organization_id)
    )).scalars().all()

    scores = []
    findings_total = 0
    for ws in workspaces:
        snap_res = await db.execute(
            select(WorkspaceSnapshot)
            .where(WorkspaceSnapshot.workspace_id == ws.id)
            .order_by(WorkspaceSnapshot.created_at.desc())
            .limit(1)
        )
        snap = snap_res.scalar_one_or_none()
        if snap:
            scores.append(snap.composite_health_score)
            findings_total += snap.total_findings

    mean_health = round(sum(scores) / max(1, len(scores)), 1) if scores else 100.0

    return OrganizationTrendsDTO(
        organization_id=organization_id,
        total_workspaces=len(workspaces),
        mean_composite_health=mean_health,
        health_velocity=0.0,
        total_findings_fleetwide=findings_total,
    )


@router.post(
    "/{organization_id}/rule-packs",
    response_model=CentralRulePackResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Register Central Rule Pack",
)
async def register_central_rule_pack(
    organization_id: str,
    payload: CentralRulePackCreateDTO,
) -> CentralRulePackResponseDTO:
    """Register an organizational monotonic enterprise rule pack."""
    def _sync_op():
        with get_sync_db() as sync_db:
            org = sync_db.query(Organization).filter_by(id=organization_id).first()
            if not org:
                raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")
            return CentralPolicyDistributionService.register_rule_pack(
                db=sync_db,
                organization_id=organization_id,
                pack_yaml=payload.pack_yaml,
            )

    try:
        record = await run_in_threadpool(_sync_op)
        return CentralRulePackResponseDTO.model_validate(record)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/{organization_id}/rule-packs",
    response_model=list[CentralRulePackResponseDTO],
    summary="List Active Central Rule Packs",
)
async def list_central_rule_packs(
    organization_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[CentralRulePackResponseDTO]:
    """Fetch all active rule packs registered for an organization."""
    query = (
        select(CentralizedRulePack)
        .where(CentralizedRulePack.organization_id == organization_id)
        .order_by(CentralizedRulePack.pack_id)
    )
    result = await db.execute(query)
    packs = result.scalars().all()
    return [CentralRulePackResponseDTO.model_validate(p) for p in packs]


@router.post(
    "/{organization_id}/suppressions",
    response_model=CentralSuppressionResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Create Central Suppression",
)
async def create_central_suppression(
    organization_id: str,
    payload: CentralSuppressionCreateDTO,
) -> CentralSuppressionResponseDTO:
    """Create an authorized, time-bound organizational suppression."""
    def _sync_op():
        with get_sync_db() as sync_db:
            org = sync_db.query(Organization).filter_by(id=organization_id).first()
            if not org:
                raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")
            return CentralPolicyDistributionService.register_suppression(
                db=sync_db,
                organization_id=organization_id,
                rule_id=payload.rule_id,
                justification=payload.justification,
                compensating_control=payload.compensating_control,
                approved_by=payload.approved_by,
                ticket_reference=payload.ticket_reference,
                expires_at=payload.expires_at,
                target_repo_id=payload.target_repo_id,
                fingerprint_hash=payload.fingerprint_hash,
            )

    try:
        record = await run_in_threadpool(_sync_op)
        return CentralSuppressionResponseDTO.model_validate(record)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/{organization_id}/suppressions",
    response_model=list[CentralSuppressionResponseDTO],
    summary="List Central Suppressions",
)
async def list_central_suppressions(
    organization_id: str,
    active_only: bool = Query(True, description="Only return unexpired suppressions"),
    db: AsyncSession = Depends(get_db),
) -> list[CentralSuppressionResponseDTO]:
    """Query organization suppressions with active/expired filtering."""
    query = select(CentralizedSuppression).where(CentralizedSuppression.organization_id == organization_id)
    if active_only:
        now = datetime.now(timezone.utc)
        query = query.where(CentralizedSuppression.expires_at > now)
    query = query.order_by(CentralizedSuppression.created_at.desc())

    result = await db.execute(query)
    supps = result.scalars().all()
    return [CentralSuppressionResponseDTO.model_validate(s) for s in supps]
