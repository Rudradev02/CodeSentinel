"""Pydantic schemas for compliance catalog and assessment endpoints (Phase 26)."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class ComplianceControlDTO(BaseModel):
    control_id: str
    framework: str
    name: str
    section: str
    description: str
    criticality: str
    guidance: str = ""
    mapped_rule_ids: list[str] = Field(default_factory=list)
    mapped_policy_ids: list[str] = Field(default_factory=list)
    framework_version: str = "1.0"
    mapping_type: Optional[str] = None
    static_limitations: list[str] = Field(default_factory=list)
    provenance: Optional[dict[str, Any]] = None


class ControlEvaluationResultDTO(BaseModel):
    control: ComplianceControlDTO
    status: str
    total_relevant_findings: int = 0
    active_violation_count: int = 0
    suppressed_violation_count: int = 0
    compliance_score: float = 1.0
    remediation_actions: list[str] = Field(default_factory=list)


class FrameworkAssessmentResultDTO(BaseModel):
    framework: str
    overall_score: float
    status: str
    total_controls: int
    compliant_controls: int
    partial_controls: int
    non_compliant_controls: int
    control_evaluations: list[ControlEvaluationResultDTO] = Field(default_factory=list)
    unresolved_violations_count: int = 0
    suppressed_exceptions_count: int = 0


class ComplianceAssessmentSuiteDTO(BaseModel):
    timestamp: str
    repository_path: str = ""
    git_commit_hash: Optional[str] = None
    config_digest: str = ""
    framework_results: dict[str, FrameworkAssessmentResultDTO] = Field(default_factory=dict)
    executive_summary: str = ""


class AttestationVerifyRequest(BaseModel):
    payload: str
    payloadType: str = "application/vnd.in-toto+json"
    signatures: list[dict[str, str]] = Field(default_factory=list)
    secret_key: str = "default-enterprise-secret"


class AttestationVerifyResponse(BaseModel):
    is_valid: bool
    message: str
    statement: Optional[dict[str, Any]] = None
