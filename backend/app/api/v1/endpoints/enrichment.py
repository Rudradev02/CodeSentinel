"""REST API endpoints for Phase 12 AI Finding Enrichment and Remediation."""

from datetime import datetime, timezone
import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.session import get_db
from backend.app.models.ai_enrichment import AIEnrichmentRecord
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.schemas.ai import (
    AIEnrichmentDTO,
    EnrichFindingAcceptedResponse,
    EnrichFindingRequest,
    ProposedPatchDTO,
)
from backend.app.workers.ai_tasks import run_ai_enrichment_task

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Enrichment"])


@router.post(
    "/{repository_id}/analyses/{analysis_id}/findings/{finding_id}/enrich",
    response_model=EnrichFindingAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue AI triage and remediation synthesis for a finding",
    description="Dispatches an asynchronous AI enrichment task to Celery and returns 202 Accepted.",
)
async def enqueue_finding_enrichment(
    repository_id: str,
    analysis_id: str,
    finding_id: str,
    request: Optional[EnrichFindingRequest] = None,
    db: AsyncSession = Depends(get_db),
) -> EnrichFindingAcceptedResponse:
    """Enqueue background AI analysis for a specific deterministic finding."""
    # 1. Enforce Repository & Snapshot Ownership
    repo_res = await db.execute(select(Repository).where(Repository.id == repository_id))
    if not repo_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository '{repository_id}' was not found.",
        )

    snap_res = await db.execute(
        select(AnalysisSnapshot).where(
            AnalysisSnapshot.id == analysis_id,
            AnalysisSnapshot.repository_id == repository_id,
        )
    )
    if not snap_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot '{analysis_id}' was not found under repository '{repository_id}'.",
        )

    finding_res = await db.execute(
        select(FindingSnapshot).where(
            FindingSnapshot.id == finding_id,
            FindingSnapshot.snapshot_id == analysis_id,
        )
    )
    finding = finding_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' was not found under snapshot '{analysis_id}'.",
        )

    req_data = request or EnrichFindingRequest()
    enrichment_id = str(uuid.uuid4())

    # 2. Dispatch Task to Celery Worker
    try:
        run_ai_enrichment_task.delay(
            finding_id=finding.id,
            provider_name=req_data.provider,
            model_name=req_data.model,
            force_refresh=req_data.force_refresh,
        )
        logger.info("Enqueued AI enrichment task for finding %s (assigned id: %s)", finding.id, enrichment_id)
    except Exception as exc:
        logger.exception("Failed to dispatch AI enrichment Celery task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AI task queue unavailable: {exc}",
        )

    return EnrichFindingAcceptedResponse(
        enrichment_id=enrichment_id,
        finding_id=finding.id,
        status="QUEUED",
        message="AI triage and remediation task queued for execution.",
    )


@router.get(
    "/{repository_id}/analyses/{analysis_id}/findings/{finding_id}/enrichment",
    response_model=AIEnrichmentDTO,
    status_code=status.HTTP_200_OK,
    summary="Retrieve AI triage and proposed remediation for a finding",
    description="Returns the persisted AI enrichment record including explanations and proposed patch.",
)
async def get_finding_enrichment(
    repository_id: str,
    analysis_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> AIEnrichmentDTO:
    """Fetch the latest AI enrichment record for a candidate finding."""
    # Enforce isolation
    snap_res = await db.execute(
        select(AnalysisSnapshot).where(
            AnalysisSnapshot.id == analysis_id,
            AnalysisSnapshot.repository_id == repository_id,
        )
    )
    if not snap_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot '{analysis_id}' not found under repository '{repository_id}'.",
        )

    query = (
        select(AIEnrichmentRecord)
        .where(
            AIEnrichmentRecord.finding_id == finding_id,
            AIEnrichmentRecord.snapshot_id == analysis_id,
        )
        .order_by(AIEnrichmentRecord.created_at.desc())
    )
    result = await db.execute(query)
    record = result.scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No AI enrichment record exists for finding '{finding_id}'.",
        )

    proposed_patch = None
    if record.proposed_patch and isinstance(record.proposed_patch, dict):
        try:
            proposed_patch = ProposedPatchDTO(**record.proposed_patch)
        except Exception as p_err:
            logger.warning("Could not deserialize proposed_patch dictionary: %s", p_err)

    limitations = []
    if record.assumptions_limitations and isinstance(record.assumptions_limitations, dict):
        limitations = record.assumptions_limitations.get("items", [])

    return AIEnrichmentDTO(
        id=record.id,
        finding_id=record.finding_id,
        snapshot_id=record.snapshot_id,
        repository_id=record.repository_id,
        status=record.status,
        provider=record.provider,
        model=record.model,
        prompt_version=record.prompt_version,
        is_likely_true_positive=record.is_likely_true_positive,
        confidence_score=record.confidence_score,
        risk_summary=record.risk_summary,
        technical_reasoning=record.technical_reasoning,
        assumptions_limitations=limitations,
        prescribed_remediation=record.prescribed_remediation,
        proposed_patch=proposed_patch,
        error_message=record.error_message,
        created_at=record.created_at,
        completed_at=record.completed_at,
    )
