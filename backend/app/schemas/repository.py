"""Pydantic DTO schemas for Repository catalog and Analysis History."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class RepositoryCreateRequest(BaseModel):
    """Request payload to register a new repository."""

    path: str = Field(
        ...,
        description="Local repository filesystem directory path to register",
        examples=["e:/AI-Workspace/projects/CodeSentinel"],
    )
    name: Optional[str] = Field(
        default=None,
        description="Optional display name for the repository (defaults to directory basename)",
        examples=["CodeSentinel"],
    )


class RepositoryResponse(BaseModel):
    """Registered repository response payload."""

    id: str = Field(..., description="Unique repository identifier")
    name: str = Field(..., description="Display name of repository")
    path: str = Field(..., description="Validated canonical filesystem path")
    created_at: datetime = Field(..., description="Registration timestamp (UTC)")
    updated_at: datetime = Field(..., description="Last update timestamp (UTC)")
    analysis_count: int = Field(default=0, ge=0, description="Total historical analyses recorded")


class RepositoryListResponse(BaseModel):
    """Paginated collection of registered repositories."""

    items: list[RepositoryResponse] = Field(default_factory=list)
    total: int = Field(..., ge=0, description="Total number of registered repositories")
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1)


class AnalysisSnapshotSummaryDTO(BaseModel):
    """Lightweight historical analysis summary record for timeline/history listing."""

    id: str = Field(..., description="Analysis snapshot run UUID")
    repository_id: str = Field(..., description="Associated repository UUID")
    created_at: datetime = Field(..., description="Analysis execution timestamp (UTC)")
    commit_hash: Optional[str] = Field(default=None, description="Git commit SHA at analysis time")
    branch: Optional[str] = Field(default=None, description="Git branch name at analysis time")
    is_dirty: Optional[bool] = Field(default=None, description="Uncommitted modifications flag")
    analyzer_version: str = Field(default="0.1.0")
    status: str = Field(default="COMPLETED")
    duration_seconds: float = Field(default=0.0, ge=0.0)
    overall_score: float = Field(..., ge=0.0, le=100.0)
    overall_grade: str = Field(..., description="A, B, C, D, F")
    architecture_score: float = Field(..., ge=0.0, le=100.0)
    architecture_grade: str = Field(...)
    security_score: float = Field(..., ge=0.0, le=100.0)
    security_grade: str = Field(...)
    total_findings: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)


class AnalysisHistoryResponse(BaseModel):
    """Paginated historical analyses response."""

    items: list[AnalysisSnapshotSummaryDTO] = Field(default_factory=list)
    total: int = Field(..., ge=0, description="Total analyses for repository")
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1)


class RunAnalysisRequest(BaseModel):
    """Optional configuration overrides when triggering a repository analysis."""

    fail_on: Optional[str] = Field(
        default=None,
        description="Optional minimum severity threshold: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )
    enabled_rules: Optional[list[str]] = Field(
        default=None,
        description="Explicit rule IDs to enable",
    )
    disabled_rules: Optional[list[str]] = Field(
        default=None,
        description="Rule IDs to disable",
    )
    max_component_depth: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum directory depth for component aggregation (default: 2)",
    )
