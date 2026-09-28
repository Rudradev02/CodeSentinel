"""Strongly-typed data models for Enterprise Compliance & Governance (Phase 26)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.obligation import ObligationKind


class ComplianceFramework(str, Enum):
    """Supported enterprise regulatory and security compliance frameworks."""
    PCI_DSS_V4_0 = "PCI_DSS_V4_0"
    HIPAA_SECURITY = "HIPAA_SECURITY"
    SOC2_TSC = "SOC2_TSC"
    NIST_SP_800_53_R5 = "NIST_SP_800_53_R5"


class ComplianceStatus(str, Enum):
    """Evaluation status of a compliance control."""
    COMPLIANT = "COMPLIANT"              # All mapped rules/policies passed without violations
    NON_COMPLIANT = "NON_COMPLIANT"      # Active unsuppressed violations detected
    PARTIALLY_COMPLIANT = "PARTIAL"      # Violations present but suppressed with active authorized exceptions
    PARTIAL = "PARTIAL"                  # Alias for PARTIALLY_COMPLIANT
    NOT_APPLICABLE = "NOT_APPLICABLE"    # Framework control not relevant to scanned technology stack


class ComplianceControl(BaseModel):
    """Formal definition of a regulatory compliance requirement or control."""
    model_config = ConfigDict(frozen=True)

    control_id: str                      # e.g., "PCI-6.2.4", "HIPAA-164.312(a)(1)", "SOC2-CC6.6", "NIST-SI-10"
    framework: ComplianceFramework
    name: str                            # e.g., "Software Vulnerability Mitigation"
    section: str                         # e.g., "Requirement 6: Develop and Maintain Secure Systems"
    description: str                     # Regulatory text summary
    mapped_rule_ids: list[str] = Field(default_factory=list)
    mapped_policy_ids: list[str] = Field(default_factory=list)
    required_obligations: list[ObligationKind] = Field(default_factory=list)
    criticality: FindingSeverity = FindingSeverity.HIGH
    guidance: str = ""                   # Auditor interpretation & remediation guidance


class ControlEvaluationResult(BaseModel):
    """Detailed evaluation result for a single compliance control."""
    control: ComplianceControl
    status: ComplianceStatus
    total_relevant_findings: int = 0
    active_violation_count: int = 0
    suppressed_violation_count: int = 0
    violating_findings: list[Finding] = Field(default_factory=list)
    suppressed_findings: list[Finding] = Field(default_factory=list)
    proof_obligation_stats: dict[str, int] = Field(default_factory=dict)
    compliance_score: float = 1.0        # 0.0 (non-compliant) to 1.0 (fully compliant)
    remediation_actions: list[str] = Field(default_factory=list)


class FrameworkAssessmentResult(BaseModel):
    """Overall compliance assessment for a given regulatory standard."""
    framework: ComplianceFramework
    overall_score: float                 # Percentage 0.0 to 100.0%
    status: ComplianceStatus
    total_controls: int
    compliant_controls: int
    partial_controls: int
    non_compliant_controls: int
    control_evaluations: list[ControlEvaluationResult] = Field(default_factory=list)
    unresolved_violations_count: int = 0
    suppressed_exceptions_count: int = 0


class ComplianceAssessmentSuite(BaseModel):
    """Complete multi-framework assessment output attached to AnalysisResult."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    repository_path: str = ""
    git_commit_hash: Optional[str] = None
    config_digest: str = ""
    framework_results: dict[str, FrameworkAssessmentResult] = Field(default_factory=dict)
    executive_summary: str = ""
