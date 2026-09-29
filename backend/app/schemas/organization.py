"""Pydantic schemas for Organization management and central policies (Phase 28)."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreateDTO(BaseModel):
    """Payload to create a new Organization."""
    name: str = Field(..., min_length=1, max_length=255, description="Display name of the organization")
    slug: Optional[str] = Field(None, max_length=100, description="URL-safe unique identifier")


class OrganizationResponseDTO(BaseModel):
    """Public representation of an Organization."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    created_at: datetime
    updated_at: datetime


class OrganizationDetailDTO(OrganizationResponseDTO):
    """Detailed organization representation including entity counts."""
    workspace_count: int = 0
    rule_pack_count: int = 0
    suppression_count: int = 0


class CentralRulePackCreateDTO(BaseModel):
    """Payload to register an organizational central rule pack."""
    pack_id: str = Field(..., min_length=1, max_length=100)
    version: str = Field(..., min_length=1, max_length=32)
    pack_yaml: str = Field(..., min_length=1, description="Raw YAML specification of the enterprise rule pack")


class CentralRulePackResponseDTO(BaseModel):
    """Representation of a registered central rule pack."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    pack_id: str
    version: str
    pack_hash: str
    created_at: datetime


class CentralSuppressionCreateDTO(BaseModel):
    """Payload to create an authorized central suppression exception."""
    rule_id: str = Field(..., min_length=1, max_length=32)
    target_repo_id: str = Field("*", max_length=36, description="Specific repository ID or '*' for org-wide")
    fingerprint_hash: Optional[str] = Field(None, max_length=64)
    justification: str = Field(..., min_length=5)
    compensating_control: str = Field(..., min_length=5)
    approved_by: str = Field(..., min_length=3, max_length=255)
    ticket_reference: str = Field(..., min_length=1, max_length=100)
    expires_at: datetime


class CentralSuppressionResponseDTO(BaseModel):
    """Representation of a registered organizational suppression."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    rule_id: str
    target_repo_id: str
    fingerprint_hash: Optional[str] = None
    justification: str
    compensating_control: str
    approved_by: str
    ticket_reference: str
    created_at: datetime
    expires_at: datetime


class OrganizationComplianceRollupDTO(BaseModel):
    """Aggregated compliance score rollup across all workspaces in an organization."""
    organization_id: str
    organization_name: str
    total_workspaces: int
    overall_health_score: float
    framework_scores: dict[str, float] = Field(default_factory=dict)
    active_violations: int = 0
    suppressed_violations: int = 0


class OrganizationTrendsDTO(BaseModel):
    """Organization-scale health velocity and trend metrics."""
    organization_id: str
    total_workspaces: int
    mean_composite_health: float
    health_velocity: float
    total_findings_fleetwide: int
