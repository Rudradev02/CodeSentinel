"""Rule metadata request and response schemas."""

from typing import Optional
from pydantic import BaseModel, Field


class RuleMetadataDTO(BaseModel):
    """Detailed metadata for a registered static analysis rule."""

    rule_id: str = Field(..., description="Unique rule ID (e.g. SEC-PY-001, ARC-005)")
    name: str = Field(..., description="Descriptive title of the rule")
    category: str = Field(..., description="Rule domain category (SECURITY or ARCHITECTURE)")
    evidence_type: str = Field(..., description="Evidence classification: DETERMINISTIC, HEURISTIC, AI_ASSISTED")
    severity: str = Field(..., description="Default severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence: str = Field(..., description="Default confidence rating: HIGH, MEDIUM, LOW")
    description: str = Field(..., description="Detailed description of vulnerability or architectural anti-pattern")
    remediation: str = Field(..., description="Recommended remediation guidance")
    supported_languages: list[str] = Field(default_factory=list, description="Target programming languages")
    frameworks: list[str] = Field(default_factory=list, description="Target frameworks")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID if applicable")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 category if applicable")
    rationale: Optional[str] = Field(default=None, description="Architectural or security justification for this rule")


class RuleListResponse(BaseModel):
    """Collection of registered static analysis rules."""

    total_rules: int = Field(..., ge=0, description="Total number of registered rules")
    rules: list[RuleMetadataDTO] = Field(..., description="List of rule metadata entries")
