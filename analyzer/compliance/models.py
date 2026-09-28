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
    PROVEN = "PROVEN"                    # Formally proven via satisfied security invariants/proof obligations
    VIOLATED = "VIOLATED"                # Active unsuppressed violations detected
    PARTIAL = "PARTIAL"                  # Violations present but covered by active authorized exceptions
    UNKNOWN = "UNKNOWN"                  # Inconclusive evidence; no formal static proof established
    NOT_ASSESSED = "NOT_ASSESSED"        # Framework control not relevant to scanned technology stack
    NOT_APPLICABLE = "NOT_APPLICABLE"    # Framework control not relevant to scanned technology stack

    # Backward compatibility aliases
    COMPLIANT = "COMPLIANT"              # Legacy alias for PROVEN / passing
    NON_COMPLIANT = "NON_COMPLIANT"      # Legacy alias for VIOLATED
    PARTIALLY_COMPLIANT = "PARTIAL"      # Legacy alias for PARTIAL

    @property
    def is_passing(self) -> bool:
        return self in (ComplianceStatus.PROVEN, ComplianceStatus.COMPLIANT)

    @property
    def is_failing(self) -> bool:
        return self in (ComplianceStatus.VIOLATED, ComplianceStatus.NON_COMPLIANT)


class MappingType(str, Enum):
    """Classification of how a static analysis rule maps to a regulatory control."""
    DIRECT = "DIRECT"                  # Rule detects exact vulnerability prohibited by control (e.g., SQLi -> PCI 6.2.4)
    SUPPORTING = "SUPPORTING"          # Rule provides hygiene evidence (e.g., circular dep -> PCI 6.3.2 architecture)
    PARTIAL = "PARTIAL"                # Rule covers only one specific clause of a compound regulatory requirement
    INFERRED = "INFERRED"              # Rule infers requirement satisfaction via framework defaults
    NOT_ASSESSABLE = "NOT_ASSESSABLE"  # Control cannot be verified via static code analysis


class ControlProvenance(BaseModel):
    """Auditable provenance and static analysis limitations for a compliance control."""
    model_config = ConfigDict(frozen=True)

    catalog_version: str = "2026.1"
    source_standard: str               # e.g., "PCI-DSS v4.0", "NIST SP 800-53 Rev 5"
    official_reference: str = ""       # e.g., "Section 6.2.4, Page 58"
    requirement_summary: str = ""
    mapping_type: MappingType = MappingType.DIRECT
    static_analysis_scope: str = ""    # Exact scope of what the AST/taint engine analyzes
    static_limitations: list[str] = Field(default_factory=list) # Explicit list of what static analysis CANNOT verify
    auditor_notes: str = ""


class ComplianceControl(BaseModel):
    """Formal definition of a regulatory compliance requirement or control."""
    model_config = ConfigDict(frozen=True)

    control_id: str                      # e.g., "PCI-6.2.4", "HIPAA-164.312(a)(1)", "SOC2-CC6.6", "NIST-SI-10"
    framework: ComplianceFramework
    framework_version: str = "1.0"       # e.g., "v4.0", "45 CFR Part 164", "2017/2022", "Rev 5"
    name: str                            # e.g., "Software Vulnerability Mitigation"
    section: str                         # e.g., "Requirement 6: Develop and Maintain Secure Systems"
    description: str                     # Regulatory text summary
    mapped_rule_ids: list[str] = Field(default_factory=list)
    mapped_policy_ids: list[str] = Field(default_factory=list)
    required_obligations: list[ObligationKind] = Field(default_factory=list)
    criticality: FindingSeverity = FindingSeverity.HIGH
    guidance: str = ""                   # Auditor interpretation & remediation guidance
    mapping_type: MappingType = MappingType.DIRECT
    static_limitations: list[str] = Field(default_factory=list)
    provenance: Optional[ControlProvenance] = None


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
    proven_obligations_count: int = 0
    violated_obligations_count: int = 0
    unknown_obligations_count: int = 0
    compliance_score: float = 1.0        # 0.0 (non-compliant) to 1.0 (fully compliant)
    remediation_actions: list[str] = Field(default_factory=list)
    limitations_noted: list[str] = Field(default_factory=list)


class FrameworkAssessmentResult(BaseModel):
    """Overall compliance assessment for a given regulatory standard."""
    framework: ComplianceFramework
    overall_score: float                 # Percentage 0.0 to 100.0%
    status: ComplianceStatus
    total_controls: int
    compliant_controls: int              # Legacy alias for proven_controls
    partial_controls: int
    non_compliant_controls: int          # Legacy alias for violated_controls
    proven_controls: int = 0
    violated_controls: int = 0
    unknown_controls: int = 0
    not_assessed_controls: int = 0
    catalog_version: str = "2026.1"
    mapping_version: str = "2026.1"
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
    disclaimer: str = (
        "Static Technical Evidence Only — Not Regulatory Certification. "
        "CodeSentinel automated assessments provide static application security analysis evidence "
        "and do not replace independent qualified auditor review or regulatory authorization."
    )
