"""Pydantic schemas for multi-repository Workspaces and workspace snapshots (Phase 28)."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class WorkspaceMemberDTO(BaseModel):
    """Member repository specification within a workspace."""
    repository_id: str
    role: str = Field("INTERNAL_SERVICE", description="PUBLIC_ENTRYPOINT, INTERNAL_SERVICE, INTERNAL_LIBRARY, DATA_LAYER, BATCH_WORKER")
    criticality: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW")
    depends_on: list[str] = Field(default_factory=list, description="IDs of repository members this member depends on")


class WorkspaceCreateDTO(BaseModel):
    """Payload to create a new multi-repository Workspace."""
    name: str = Field(..., min_length=1, max_length=255)
    slug: Optional[str] = Field(None, max_length=100)
    manifest_path: str = Field(..., min_length=1, max_length=1024)
    config_payload: Optional[dict[str, Any]] = None
    repositories: list[WorkspaceMemberDTO] = Field(default_factory=list)


class WorkspaceResponseDTO(BaseModel):
    """Public representation of a Workspace."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    name: str
    slug: str
    manifest_path: str
    config_payload: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class WorkspaceDetailDTO(WorkspaceResponseDTO):
    """Detailed workspace representation including topology members and latest score."""
    repositories: list[WorkspaceMemberDTO] = Field(default_factory=list)
    execution_waves: list[list[str]] = Field(default_factory=list)
    latest_snapshot_id: Optional[str] = None
    composite_health_score: Optional[float] = None
    composite_grade: Optional[str] = None


class WorkspaceScanRequestDTO(BaseModel):
    """Optional parameters when triggering an asynchronous workspace scan."""
    manifest_path: Optional[str] = None


class WorkspaceScanResponseDTO(BaseModel):
    """Immediate response after enqueueing a workspace scan task."""
    workspace_id: str
    task_id: str
    status: str = "ACCEPTED"
    message: str = "Workspace analysis task successfully enqueued"


class WorkspaceSnapshotSummaryDTO(BaseModel):
    """Summary representation of a completed Workspace analysis snapshot."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    created_at: datetime
    composite_health_score: float
    composite_grade: str
    total_findings: int
    critical_findings: int
    high_findings: int
    merkle_workspace_root: str


class WorkspaceSnapshotDetailDTO(WorkspaceSnapshotSummaryDTO):
    """Full composite workspace snapshot including attestation and compliance rollups."""
    attestation_envelope: Optional[dict[str, Any]] = None
    compliance_suite: Optional[dict[str, Any]] = None
    repository_snapshot_ids: list[str] = Field(default_factory=list)
