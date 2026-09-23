"""Pydantic schemas for Phase 12 AI Enrichment, False-Positive Triage, and Remediation."""

from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class ProposedPatchDTO(BaseModel):
    """Structured remediation patch proposal targeting the finding location."""

    file_path: str = Field(..., description="Target repository-relative file path")
    original_snippet: str = Field(..., description="Original code block to replace")
    patched_snippet: str = Field(..., description="Proposed replacement code block")
    unified_diff: str = Field(..., description="Standard unified diff format (--- a/ ... +++ b/ ...)")
    explanation: str = Field(..., description="Rationale explaining how this patch resolves the vulnerability")


class AIFindingEnrichmentDTO(BaseModel):
    """Raw structured output schema expected from the LLM."""

    finding_id: str = Field(..., description="Target finding UUID")
    is_likely_true_positive: bool = Field(..., description="Whether finding is evaluated as true positive")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment (0.0 to 1.0)")
    risk_summary: str = Field(..., description="Executive risk assessment")
    technical_reasoning: str = Field(..., description="Technical explanation")
    assumptions_and_limitations: List[str] = Field(default_factory=list, description="Assumptions made")
    prescribed_remediation: str = Field(..., description="Remediation guidance")
    proposed_patch: Optional[ProposedPatchDTO] = Field(default=None, description="Proposed unified diff patch")


class AIEnrichmentDTO(BaseModel):
    """Complete AI enrichment and advisory triage payload for a finding."""


    id: str = Field(..., description="Enrichment record UUID")
    finding_id: str = Field(..., description="Target finding snapshot UUID")
    snapshot_id: str = Field(..., description="Target analysis snapshot UUID")
    repository_id: str = Field(..., description="Parent repository UUID")
    status: str = Field(..., description="Enrichment status: QUEUED, RUNNING, COMPLETED, FAILED, DISABLED")
    provider: str = Field(..., description="AI provider used (openrouter, ollama)")
    model: str = Field(..., description="Model identifier used for inference")
    prompt_version: str = Field(default="v1", description="Prompt template version identifier")

    # Advisory Analysis Results
    is_likely_true_positive: Optional[bool] = Field(
        default=None,
        description="Whether static finding is evaluated as a genuine vulnerability in context",
    )
    confidence_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score in the triage assessment (0.0 to 1.0)",
    )
    risk_summary: Optional[str] = Field(
        default=None,
        description="Concise executive summary of practical exploitability and blast radius",
    )
    technical_reasoning: Optional[str] = Field(
        default=None,
        description="In-depth technical explanation of data flow, attack vectors, and defenses",
    )
    assumptions_limitations: List[str] = Field(
        default_factory=list,
        description="Contextual assumptions, missing runtime signals, or analysis limitations",
    )
    prescribed_remediation: Optional[str] = Field(
        default=None,
        description="Prescriptive architectural or implementation guidance",
    )
    proposed_patch: Optional[ProposedPatchDTO] = Field(
        default=None,
        description="Validated proposed unified diff patch, if sufficient context was available",
    )

    error_message: Optional[str] = Field(
        default=None,
        description="Error details if the enrichment pipeline failed",
    )
    created_at: datetime = Field(..., description="Record creation timestamp in UTC")
    completed_at: Optional[datetime] = Field(default=None, description="Record completion timestamp in UTC")


class EnrichFindingRequest(BaseModel):
    """Request payload to initiate AI triage and remediation on a finding."""

    provider: Optional[str] = Field(
        default=None,
        description="Optional provider override: 'openrouter' or 'ollama' (defaults to system config)",
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional model override (defaults to system config for selected provider)",
    )
    force_refresh: bool = Field(
        default=False,
        description="Bypass database cache and regenerate enrichment from LLM",
    )


class EnrichFindingAcceptedResponse(BaseModel):
    """Asynchronous acceptance response returned when an enrichment task is enqueued."""

    enrichment_id: str = Field(..., description="Enrichment job UUID for tracking")
    finding_id: str = Field(..., description="Target finding snapshot UUID")
    status: str = Field(default="QUEUED", description="Current status of the enrichment task")
    message: str = Field(..., description="Human-readable status summary")
