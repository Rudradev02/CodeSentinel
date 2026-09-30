"""REST API endpoints for Phase 30 Natural-Language Policy Authoring & Approval."""

from datetime import datetime, timezone
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from analyzer.rules.policy import PolicyEnforcementMode, SecurityPolicy
from analyzer.rules.policy_authoring import PolicyValidationStatus, SemanticPolicyValidator
from backend.app.db.session import get_db
from backend.app.models.triage_feedback import AIPolicyProposalRecord
from backend.app.schemas.phase30 import (
    PolicyApproveRequest,
    PolicyApproveResponse,
    PolicyAuthorRequest,
    PolicyAuthorResponse,
)
from backend.app.services.ai.policy_service import NaturalLanguagePolicyService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Policy Studio"])


@router.post(
    "/policies/ai-author",
    response_model=PolicyAuthorResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate natural language prompt into structured SecurityPolicy candidate",
)
async def author_policy_from_natural_language(
    req: PolicyAuthorRequest,
    db: AsyncSession = Depends(get_db),
) -> PolicyAuthorResponse:
    """Translate high-level natural language security requirement into a declarative policy candidate."""
    status_enum, candidate_json, diagnostics = NaturalLanguagePolicyService.translate_prompt_to_candidate(
        natural_language_input=req.prompt,
    )

    proposal_id: Optional[str] = None
    policy_id: Optional[str] = None

    if candidate_json:
        policy_id = candidate_json.get("policy_id", f"POL-DRAFT-{int(datetime.now(timezone.utc).timestamp())}")

        # Check for existing policy_id collision
        existing_res = await db.execute(
            select(AIPolicyProposalRecord).where(AIPolicyProposalRecord.policy_id == policy_id)
        )
        if existing_res.scalar_one_or_none():
            policy_id = f"{policy_id}-{int(datetime.now(timezone.utc).timestamp())}"
            candidate_json["policy_id"] = policy_id

        record = AIPolicyProposalRecord(
            policy_id=policy_id,
            natural_language_prompt=req.prompt,
            generated_policy_json=candidate_json,
            validation_status=status_enum.value,
            validation_diagnostics={"diagnostics": diagnostics},
            author_id=req.author_id,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        proposal_id = record.id

    return PolicyAuthorResponse(
        proposal_id=proposal_id,
        policy_id=policy_id,
        validation_status=status_enum.value,
        candidate_policy=candidate_json,
        diagnostics=diagnostics,
    )


@router.post(
    "/policies/{policy_id}/approve",
    response_model=PolicyApproveResponse,
    status_code=status.HTTP_200_OK,
    summary="Review and formally activate an AI-generated policy with auditor credentials",
)
async def approve_security_policy(
    policy_id: str,
    req: PolicyApproveRequest,
    db: AsyncSession = Depends(get_db),
) -> PolicyApproveResponse:
    """Formal human approval gate activating candidate policy into authoritative registry."""
    query = select(AIPolicyProposalRecord).where(
        (AIPolicyProposalRecord.policy_id == policy_id) | (AIPolicyProposalRecord.id == policy_id)
    )
    result = await db.execute(query)
    proposal = result.scalar_one_or_none()

    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy candidate '{policy_id}' was not found.",
        )

    if proposal.approved_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy '{proposal.policy_id}' has already been approved and activated.",
        )

    # Re-validate candidate JSON
    val_status, policy, diagnostics = SemanticPolicyValidator.validate(
        proposal.generated_policy_json,
        raw_prompt=proposal.natural_language_prompt,
    )

    if val_status != PolicyValidationStatus.VALIDATED_CANDIDATE or policy is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Policy candidate failed semantic validation: {diagnostics}",
        )

    # Update proposal record
    now = datetime.now(timezone.utc)
    proposal.approved_by = req.approved_by
    proposal.approved_at = now
    proposal.validation_status = "APPROVED_ACTIVE"
    await db.commit()
    await db.refresh(proposal)

    return PolicyApproveResponse(
        policy_id=proposal.policy_id,
        status="APPROVED_ACTIVE",
        approved_by=req.approved_by,
        approved_at=now,
        policy=proposal.generated_policy_json,
    )
