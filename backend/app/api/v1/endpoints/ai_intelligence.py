"""REST API endpoints for Phase 30 AI intelligence, triage feedback, prioritization, and refactoring."""

from datetime import datetime, timezone
import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from analyzer.architecture.refactoring_simulator import DeterministicRefactoringSimulator, RefactoringProposalDTO
from analyzer.models.boundary import AuthenticationState, AuthorizationState, TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.security.exploitability import InputControllabilityLevel, PathFeasibilityLevel
from backend.app.db.session import get_db
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.triage_feedback import (
    AIPrioritizationRecord,
    AIRefactoringProposalRecord,
    FindingTriageFeedbackRecord,
)
from backend.app.schemas.phase30 import (
    PrioritizeFindingRequest,
    PrioritizationResponse,
    RefactorProposalResponse,
    RefactorSimulationRequest,
    RefactorSimulationResponse,
    TriageFeedbackRequest,
    TriageFeedbackResponse,
)
from backend.app.services.ai.prioritizer import AIPrioritizerService
from backend.app.services.ai.triage_ml.features import FeatureExtractor

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Intelligence"])


@router.post(
    "/{repository_id}/analyses/{analysis_id}/findings/{finding_id}/feedback",
    response_model=TriageFeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record human triage feedback for false positive reduction",
)
async def record_triage_feedback(
    repository_id: str,
    analysis_id: str,
    finding_id: str,
    req: TriageFeedbackRequest,
    db: AsyncSession = Depends(get_db),
) -> TriageFeedbackResponse:
    """Record human security reviewer triage verdict to build ground truth training dataset."""
    valid_labels = {"TRUE_POSITIVE", "FALSE_POSITIVE", "ACCEPTED_RISK", "SUSPECT_HEURISTIC"}
    clean_label = req.label.strip().upper()
    if clean_label not in valid_labels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid label '{req.label}'. Allowed values: {sorted(valid_labels)}",
        )

    # Verify FindingSnapshot and ownership
    find_res = await db.execute(
        select(FindingSnapshot).where(
            FindingSnapshot.id == finding_id,
            FindingSnapshot.snapshot_id == analysis_id,
        )
    )
    finding = find_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found under analysis '{analysis_id}'.",
        )

    # Extract 18 non-sensitive tabular features
    features = FeatureExtractor.extract_features(finding=finding)

    record = FindingTriageFeedbackRecord(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        finding_fingerprint=finding.finding_uuid,
        snapshot_id=analysis_id,
        repository_id=repository_id,
        rule_id=finding.rule_id,
        label=clean_label,
        reason=req.reason.strip(),
        reviewer_id=req.reviewer_id.strip(),
        feature_snapshot=features,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    return TriageFeedbackResponse(
        feedback_id=record.id,
        finding_id=finding.id,
        label=clean_label,
        recorded_at=record.created_at,
        features_recorded=features is not None,
    )


@router.get(
    "/{repository_id}/analyses/{analysis_id}/findings/{finding_id}/priority",
    response_model=PrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve exploitability breakdown and Priority Score (P0-P3)",
)
async def get_finding_priority(
    repository_id: str,
    analysis_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> PrioritizationResponse:
    """Retrieve exploitability breakdown and Priority Score for a finding."""
    p_res = await db.execute(
        select(AIPrioritizationRecord)
        .where(
            AIPrioritizationRecord.finding_id == finding_id,
            AIPrioritizationRecord.snapshot_id == analysis_id,
        )
        .order_by(AIPrioritizationRecord.created_at.desc())
    )
    record = p_res.scalars().first()

    if record:
        return PrioritizationResponse(
            finding_id=record.finding_id,
            rule_id="RULE-RESOLVED",
            severity="CRITICAL",
            priority_score=record.priority_score,
            priority_band=record.priority_band,
            exploitability_score=record.exploitability_score,
            contributing_factors=record.contributing_factors or {},
            rationale=record.reasoning_summary,
            context_hash=record.context_hash,
        )

    # Compute on the fly if not yet persisted
    find_res = await db.execute(
        select(FindingSnapshot).where(
            FindingSnapshot.id == finding_id,
            FindingSnapshot.snapshot_id == analysis_id,
        )
    )
    finding = find_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    res = AIPrioritizerService.prioritize_finding(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        confidence=finding.confidence,
        evidence_snippet=finding.snippet or "",
    )

    return PrioritizationResponse(
        finding_id=res["finding_id"],
        rule_id=res["rule_id"],
        severity=res["severity"],
        priority_score=res["priority_score"],
        priority_band=res["priority_band"],
        exploitability_score=res["exploitability_score"],
        contributing_factors=res["contributing_factors"],
        rationale=res["rationale"],
        breakdown=res.get("breakdown"),
        context_hash=res["context_hash"],
    )


@router.post(
    "/{repository_id}/analyses/{analysis_id}/findings/{finding_id}/prioritize",
    response_model=PrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger on-demand AI exploitability evaluation",
)
async def trigger_finding_prioritization(
    repository_id: str,
    analysis_id: str,
    finding_id: str,
    req: PrioritizeFindingRequest,
    db: AsyncSession = Depends(get_db),
) -> PrioritizationResponse:
    """Trigger on-demand exploitability analysis and Priority Score calculation."""
    find_res = await db.execute(
        select(FindingSnapshot).where(
            FindingSnapshot.id == finding_id,
            FindingSnapshot.snapshot_id == analysis_id,
        )
    )
    finding = find_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    # Determine boundary and input controllability heuristics from rule / snippet
    is_http = any(term in (finding.file_path + " " + (finding.snippet or "")).lower() for term in ["route", "api", "request", "http", "view"])
    boundary = TrustBoundaryType.HTTP_REQUEST_PARAM if is_http else TrustBoundaryType.INTERNAL_SERVICE
    auth = AuthenticationState.UNAUTHENTICATED if is_http else AuthenticationState.AUTHENTICATED
    authz = AuthorizationState.UNAUTHORIZED if is_http else AuthorizationState.ROLE_VERIFIED

    res = AIPrioritizerService.prioritize_finding(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        confidence=finding.confidence,
        boundary=boundary,
        auth_state=auth,
        authz_state=authz,
        input_controllability=InputControllabilityLevel.DIRECT_STRING_CONCAT if "execute(" in (finding.snippet or "") else InputControllabilityLevel.STRUCTURED_PARAM_MAPPING,
        path_feasibility=PathFeasibilityLevel.UNCONDITIONAL_FLOW,
        evidence_snippet=finding.snippet or "",
        asset_criticality=req.asset_criticality or 1.0,
    )

    # Persist in DB
    prioritization_record = AIPrioritizationRecord(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        snapshot_id=analysis_id,
        priority_score=res["priority_score"],
        priority_band=res["priority_band"],
        exploitability_score=res["exploitability_score"],
        contributing_factors=res["contributing_factors"],
        reasoning_summary=res["rationale"],
        context_hash=res["context_hash"],
    )
    db.add(prioritization_record)
    await db.commit()
    await db.refresh(prioritization_record)

    return PrioritizationResponse(
        finding_id=res["finding_id"],
        rule_id=res["rule_id"],
        severity=res["severity"],
        priority_score=res["priority_score"],
        priority_band=res["priority_band"],
        exploitability_score=res["exploitability_score"],
        contributing_factors=res["contributing_factors"],
        rationale=res["rationale"],
        breakdown=res.get("breakdown"),
        context_hash=res["context_hash"],
    )


@router.get(
    "/{repository_id}/analyses/{analysis_id}/refactor-proposals",
    response_model=list[RefactorProposalResponse],
    status_code=status.HTTP_200_OK,
    summary="List architectural refactoring proposals with simulated metric deltas",
)
async def list_refactor_proposals(
    repository_id: str,
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[RefactorProposalResponse]:
    """Retrieve all simulated architectural refactoring proposals for a snapshot."""
    query = (
        select(AIRefactoringProposalRecord)
        .where(
            AIRefactoringProposalRecord.repository_id == repository_id,
            AIRefactoringProposalRecord.snapshot_id == analysis_id,
        )
        .order_by(AIRefactoringProposalRecord.created_at.desc())
    )
    result = await db.execute(query)
    proposals = result.scalars().all()

    return [
        RefactorProposalResponse(
            id=p.id,
            target_rule_id=p.target_rule_id,
            refactoring_type=p.refactoring_type,
            title=p.title,
            problem_statement=p.problem_statement,
            proposed_design=p.proposed_design,
            affected_components=p.affected_components or [],
            affected_files=p.affected_files or [],
            hypothetical_edge_mutations=p.hypothetical_edge_mutations or [],
            simulated_metric_deltas=p.simulated_metric_deltas,
            simulation_status=p.simulation_status,
            status=p.status,
            created_at=p.created_at,
        )
        for p in proposals
    ]


@router.post(
    "/{repository_id}/analyses/{analysis_id}/refactor-proposals/{proposal_id}/simulate",
    response_model=RefactorSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Rerun deterministic graph simulation with modified parameters",
)
async def simulate_refactoring(
    repository_id: str,
    analysis_id: str,
    proposal_id: str,
    req: RefactorSimulationRequest,
    db: AsyncSession = Depends(get_db),
) -> RefactorSimulationResponse:
    """Rerun deterministic NetworkX graph simulation for modified hypothetical edge mutations."""
    p_res = await db.execute(
        select(AIRefactoringProposalRecord).where(
            AIRefactoringProposalRecord.id == proposal_id,
            AIRefactoringProposalRecord.snapshot_id == analysis_id,
        )
    )
    proposal_record = p_res.scalar_one_or_none()
    if not proposal_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Refactoring proposal '{proposal_id}' was not found.",
        )

    # Re-run simulation
    import networkx as nx
    G = nx.DiGraph()
    for comp in (proposal_record.affected_components or []):
        G.add_node(comp)

    # Add default test cycle edges for simulation
    if len(proposal_record.affected_components or []) >= 2:
        comps = proposal_record.affected_components or []
        for i in range(len(comps)):
            G.add_edge(comps[i], comps[(i + 1) % len(comps)])

    proposal_dto = RefactoringProposalDTO(
        proposal_id=proposal_record.id,
        target_rule_id=proposal_record.target_rule_id,
        refactoring_type=proposal_record.refactoring_type,
        title=proposal_record.title,
        problem_statement=proposal_record.problem_statement,
        proposed_design=proposal_record.proposed_design,
        affected_components=proposal_record.affected_components or [],
        hypothetical_edge_mutations=req.hypothetical_edge_mutations,
    )

    sim_result = DeterministicRefactoringSimulator.simulate_proposal(G, proposal_dto)

    # Update proposal record in DB
    proposal_record.hypothetical_edge_mutations = req.hypothetical_edge_mutations
    proposal_record.simulated_metric_deltas = sim_result.metric_deltas
    proposal_record.simulation_status = sim_result.simulation_status
    await db.commit()

    return RefactorSimulationResponse(
        simulation_status=sim_result.simulation_status,
        target_cycle_eliminated=sim_result.target_cycle_eliminated,
        cycles_before_count=sim_result.cycles_before_count,
        cycles_after_count=sim_result.cycles_after_count,
        new_cycles_detected=sim_result.new_cycles_detected,
        metric_deltas=sim_result.metric_deltas,
        sdp_violations=sim_result.sdp_violations,
        diagnostics=sim_result.diagnostics,
    )
