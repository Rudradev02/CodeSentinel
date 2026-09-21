"""Comparison request and response DTO schemas for CodeSentinel differential analysis (Phase 9)."""

from typing import Any, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.analysis import FindingDTO


class CompareRequest(BaseModel):
    """Request payload to initiate differential comparison between baseline and current."""

    baseline_path: Optional[str] = Field(
        default=None,
        description="Path to baseline repository directory OR baseline report JSON file",
    )
    current_path: Optional[str] = Field(
        default=None,
        description="Path to current repository directory OR current report JSON file",
    )
    baseline_json: Optional[dict[str, Any]] = Field(
        default=None,
        description="Direct baseline AnalysisResult JSON dictionary (from file upload / client)",
    )
    current_json: Optional[dict[str, Any]] = Field(
        default=None,
        description="Direct current AnalysisResult JSON dictionary (from file upload / client)",
    )


class DifferentialFindingDTO(BaseModel):
    """Finding DTO augmented with transition state."""

    finding: FindingDTO
    transition: str = Field(..., description="NEW, RESOLVED, UNCHANGED, or MODIFIED")
    baseline_finding_id: Optional[str] = None
    match_method: Optional[str] = None
    detail: Optional[str] = None


class HealthDeltaDTO(BaseModel):
    """Calculated delta in codebase health score and grade."""

    score_delta: float
    baseline_score: Optional[float] = None
    current_score: Optional[float] = None
    baseline_grade: Optional[str] = None
    current_grade: Optional[str] = None
    grade_changed: bool = False
    architecture_score_delta: Optional[float] = None
    security_score_delta: Optional[float] = None


class ComponentDeltaDTO(BaseModel):
    """Structural delta in component topology and stability."""

    new_components: list[str] = Field(default_factory=list)
    removed_components: list[str] = Field(default_factory=list)
    instability_deltas: dict[str, float] = Field(default_factory=dict)
    new_cycles: list[list[str]] = Field(default_factory=list)
    resolved_cycles: list[list[str]] = Field(default_factory=list)


class ComparisonSummaryDTO(BaseModel):
    """High-level counters summarizing finding transitions."""

    total_current: int
    total_baseline: int
    new_count: int
    resolved_count: int
    unchanged_count: int
    modified_count: int
    new_by_severity: dict[str, int] = Field(default_factory=dict)
    resolved_by_severity: dict[str, int] = Field(default_factory=dict)


class ComparisonResponseDTO(BaseModel):
    """Client-facing response model for baseline differential comparison."""

    baseline_id: Optional[str] = None
    current_id: str
    baseline_commit: Optional[str] = None
    current_commit: Optional[str] = None
    compared_at: str
    summary: ComparisonSummaryDTO
    findings: list[DifferentialFindingDTO] = Field(default_factory=list)
    health_delta: Optional[HealthDeltaDTO] = None
    component_delta: Optional[ComponentDeltaDTO] = None
