"""Pydantic schemas for Phase 30 AI Intelligence REST API."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class TriageFeedbackRequest(BaseModel):
    label: str = Field(..., description="TRUE_POSITIVE, FALSE_POSITIVE, ACCEPTED_RISK, or SUSPECT_HEURISTIC")
    reason: str = Field(default="", description="Human reviewer justification")
    reviewer_id: str = Field(..., description="Reviewer email or identity")


class TriageFeedbackResponse(BaseModel):
    feedback_id: str
    finding_id: str
    label: str
    recorded_at: datetime
    features_recorded: bool


class PrioritizeFindingRequest(BaseModel):
    asset_criticality: Optional[float] = Field(default=1.0, ge=0.5, le=2.0)
    force_refresh: bool = False


class PrioritizationResponse(BaseModel):
    finding_id: str
    rule_id: str
    severity: str
    priority_score: float
    priority_band: str
    exploitability_score: float
    contributing_factors: dict[str, Any]
    rationale: str
    breakdown: Optional[dict[str, Any]] = None
    context_hash: str


class PolicyAuthorRequest(BaseModel):
    prompt: str = Field(..., min_length=5, description="Natural-language security requirement")
    author_id: str = Field(..., description="User identity authoring the policy")


class PolicyAuthorResponse(BaseModel):
    proposal_id: Optional[str]
    policy_id: Optional[str]
    validation_status: str
    candidate_policy: Optional[dict[str, Any]]
    diagnostics: list[str]


class PolicyApproveRequest(BaseModel):
    approved_by: str = Field(..., description="Auditor / security administrator identity")


class PolicyApproveResponse(BaseModel):
    policy_id: str
    status: str
    approved_by: str
    approved_at: datetime
    policy: dict[str, Any]


class RefactorSimulationRequest(BaseModel):
    hypothetical_edge_mutations: list[dict[str, str]]


class RefactorSimulationResponse(BaseModel):
    simulation_status: str
    target_cycle_eliminated: bool
    cycles_before_count: int
    cycles_after_count: int
    new_cycles_detected: list[list[str]]
    metric_deltas: dict[str, dict[str, float]]
    sdp_violations: list[str]
    diagnostics: list[str]


class RefactorProposalResponse(BaseModel):
    id: str
    target_rule_id: str
    refactoring_type: str
    title: str
    problem_statement: str
    proposed_design: str
    affected_components: list[str]
    affected_files: list[str]
    hypothetical_edge_mutations: list[dict[str, str]]
    simulated_metric_deltas: Optional[dict[str, Any]]
    simulation_status: str
    status: str
    created_at: datetime
