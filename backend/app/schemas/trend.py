"""Longitudinal trend and historical trajectory schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class TimelinePoint(BaseModel):
    """Snapshot point along repository analysis timeline."""

    snapshot_id: str = Field(..., description="Analysis snapshot UUID")
    created_at: datetime = Field(..., description="Analysis run completion timestamp")
    commit_hash: Optional[str] = Field(default=None, description="Git commit hash")
    branch: Optional[str] = Field(default=None, description="Git branch")
    overall_score: float = Field(..., description="Overall health score (0-100)")
    architecture_score: float = Field(..., description="Architecture health score (0-100)")
    security_score: float = Field(..., description="Security health score (0-100)")
    overall_grade: str = Field(..., description="Overall grade (A-F)")
    total_findings: int = Field(..., description="Total finding count")
    critical_count: int = Field(default=0, description="Critical finding count")
    high_count: int = Field(default=0, description="High finding count")
    medium_count: int = Field(default=0, description="Medium finding count")
    low_count: int = Field(default=0, description="Low finding count")
    info_count: int = Field(default=0, description="Info finding count")


class DefectVelocityPoint(BaseModel):
    """Defect velocity metric between successive snapshots."""

    snapshot_id: str = Field(..., description="Analysis snapshot UUID")
    created_at: datetime = Field(..., description="Analysis completion timestamp")
    new_defects: int = Field(default=0, description="Defects newly introduced in this snapshot")
    resolved_defects: int = Field(default=0, description="Defects resolved since previous snapshot")
    net_change: int = Field(default=0, description="Net defect change (new - resolved)")


class ComponentDriftSummary(BaseModel):
    """Instability and structural metric drift for a component over time."""

    component_id: str = Field(..., description="Component identifier/path")
    name: str = Field(..., description="Human readable component name")
    baseline_instability: Optional[float] = Field(default=None, description="Earliest recorded instability (0-1)")
    current_instability: float = Field(..., description="Most recent instability (0-1)")
    instability_drift: float = Field(..., description="Instability delta (current - baseline)")
    current_centrality: float = Field(default=0.0, description="Most recent betweenness centrality")


class LongitudinalTrendDTO(BaseModel):
    """Comprehensive longitudinal intelligence analysis for a repository."""

    repository_id: str = Field(..., description="Repository UUID")
    branch: Optional[str] = Field(default=None, description="Branch filter applied, if any")
    total_snapshots: int = Field(..., description="Total snapshots analyzed in window")
    window_days: Optional[int] = Field(default=None, description="Lookback window in days, if specified")
    health_trajectory: list[TimelinePoint] = Field(default_factory=list, description="Chronological health metrics")
    defect_velocity: list[DefectVelocityPoint] = Field(default_factory=list, description="Defect velocity per transition")
    severity_trajectories: dict[str, list[int]] = Field(
        default_factory=dict,
        description="Severity volume series keyed by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )
    component_drift: list[ComponentDriftSummary] = Field(default_factory=list, description="Component architectural drift")
    overall_health_delta: float = Field(default=0.0, description="Net score change from first to last snapshot in window")
    defect_burndown_rate: float = Field(default=0.0, description="Ratio of resolved defects to introduced defects")
