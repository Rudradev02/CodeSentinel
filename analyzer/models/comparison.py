"""Differential comparison models for CodeSentinel baseline analysis (Phase 9, extended Phase 25)."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from typing import Optional
from pydantic import BaseModel, Field

from analyzer.models.findings import Finding


class FindingTransition(str, Enum):
    """Transition state of a finding relative to baseline."""
    NEW = "NEW"              # Introduced in current run (regression)
    RESOLVED = "RESOLVED"    # Present in baseline but fixed in current run
    UNCHANGED = "UNCHANGED"  # Present in both baseline and current run
    MODIFIED = "MODIFIED"    # Same logical defect, but location/snippet shifted


class FindingLifecycleState(str, Enum):
    """Extended lifecycle state of a finding across analysis runs (Phase 25).

    Superset of FindingTransition with additional states for suppressions,
    policy-induced changes, and regression classification.
    """
    # Core transitions (backward-compatible with FindingTransition)
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"
    MODIFIED = "MODIFIED"

    # Suppression states
    SUPPRESSED = "SUPPRESSED"
    DEFERRED = "DEFERRED"
    REOPENED = "REOPENED"

    # Policy-induced states
    POLICY_INDUCED_NEW = "POLICY_INDUCED_NEW"
    POLICY_INDUCED_RESOLVED = "POLICY_INDUCED_RESOLVED"

    # Regression classification
    REGRESSION = "REGRESSION"
    PERSISTENT = "PERSISTENT"


class DifferentialFinding(BaseModel):
    """Finding augmented with baseline differential transition metadata."""
    finding: Finding
    transition: FindingTransition
    baseline_finding_id: Optional[str] = None
    match_method: Optional[str] = None  # "id", "exact_signature", "fuzzy_snippet", "fuzzy_location", "fingerprint"
    detail: Optional[str] = None
    # Phase 25 extensions (additive, backward-compatible)
    lifecycle_state: Optional[FindingLifecycleState] = None
    regression: Optional[Any] = None  # RegressionClassification (from analyzer.comparison.regression)
    suppression: Optional[Any] = None  # FindingSuppression (from analyzer.models.suppression)


class HealthDelta(BaseModel):
    """Calculated delta between baseline and current codebase health ratings."""
    score_delta: float = Field(..., description="current.overall_score - baseline.overall_score")
    baseline_score: Optional[float] = None
    current_score: Optional[float] = None
    baseline_grade: Optional[str] = None
    current_grade: Optional[str] = None
    grade_changed: bool = False
    architecture_score_delta: Optional[float] = None
    security_score_delta: Optional[float] = None


class ComponentGraphDelta(BaseModel):
    """Structural deltas in component topology and stability metrics."""
    new_components: list[str] = Field(default_factory=list)
    removed_components: list[str] = Field(default_factory=list)
    instability_deltas: dict[str, float] = Field(default_factory=dict)
    new_cycles: list[list[str]] = Field(default_factory=list)
    resolved_cycles: list[list[str]] = Field(default_factory=list)


class ComparisonSummary(BaseModel):
    """High-level counters summarizing differential analysis results."""
    total_current: int = Field(default=0, ge=0)
    total_baseline: int = Field(default=0, ge=0)
    new_count: int = Field(default=0, ge=0)
    resolved_count: int = Field(default=0, ge=0)
    unchanged_count: int = Field(default=0, ge=0)
    modified_count: int = Field(default=0, ge=0)
    new_by_severity: dict[str, int] = Field(default_factory=dict)
    resolved_by_severity: dict[str, int] = Field(default_factory=dict)
    # Phase 25 lifecycle counters (additive, backward-compatible)
    suppressed_count: int = Field(default=0, ge=0)
    deferred_count: int = Field(default=0, ge=0)
    reopened_count: int = Field(default=0, ge=0)
    policy_induced_new_count: int = Field(default=0, ge=0)
    policy_induced_resolved_count: int = Field(default=0, ge=0)
    regression_count: int = Field(default=0, ge=0)
    pre_existing_count: int = Field(default=0, ge=0)
    gate_verdict: Optional[str] = None


class ComparisonResult(BaseModel):
    """Deterministic comparison between a baseline AnalysisResult and current AnalysisResult."""
    baseline_id: Optional[str] = None
    current_id: str
    baseline_commit: Optional[str] = None
    current_commit: Optional[str] = None
    compared_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: ComparisonSummary
    findings: list[DifferentialFinding] = Field(default_factory=list)
    health_delta: Optional[HealthDelta] = None
    component_delta: Optional[ComponentGraphDelta] = None
