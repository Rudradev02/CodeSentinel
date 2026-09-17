"""Strongly-typed findings and classification models for CodeSentinel."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid
from pydantic import BaseModel, Field, field_validator, model_validator


class EvidenceType(str, Enum):
    """Categorization of finding evidence source."""
    DETERMINISTIC = "DETERMINISTIC"  # AST/rule-based evidence with explicit conditions
    HEURISTIC = "HEURISTIC"          # Pattern/context-based analysis where confidence depends on evidence
    AI_ASSISTED = "AI_ASSISTED"      # LLM-generated explanation, validation, or remediation


class FindingSeverity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, Enum):
    """Confidence levels for static detection accuracy."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, Enum):
    """Domain category of the finding."""
    SECURITY = "SECURITY"
    ARCHITECTURE = "ARCHITECTURE"
    QUALITY = "QUALITY"


class AIValidationStatus(str, Enum):
    """Assessment status assigned by the AI enrichment pipeline."""
    CONFIRMED = "CONFIRMED"
    PROBABLE_FALSE_POSITIVE = "PROBABLE_FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class SourceLocation(BaseModel):
    """Precise source code coordinate for a finding."""
    file_path: str = Field(..., description="Path to file relative to repository root")
    line_start: int = Field(..., ge=1, description="Starting line number (1-indexed)")
    line_end: int = Field(..., ge=1, description="Ending line number (1-indexed)")
    col_start: Optional[int] = Field(default=None, ge=0, description="Starting column offset")
    col_end: Optional[int] = Field(default=None, ge=0, description="Ending column offset")

    @model_validator(mode="after")
    def validate_line_range(self) -> "SourceLocation":
        if self.line_start > self.line_end:
            raise ValueError(f"line_start ({self.line_start}) cannot exceed line_end ({self.line_end})")
        return self


class RuleDefinition(BaseModel):
    """Formal definition and metadata of an audit rule."""
    rule_id: str = Field(..., min_length=3, description="Unique identifier (e.g. SEC-PY-001)")
    name: str = Field(..., min_length=3, description="Descriptive title of the rule")
    category: FindingCategory
    evidence_type: EvidenceType
    severity: FindingSeverity
    confidence: FindingConfidence
    description: str = Field(..., description="Explanation of the vulnerability or anti-pattern")
    remediation: str = Field(..., description="Prescribed remediation steps")
    languages: list[str] = Field(default_factory=list, description="Target languages")
    frameworks: list[str] = Field(default_factory=list, description="Target frameworks")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 category")


class AIFindingEnrichment(BaseModel):
    """Contextual assessment and remediation suggestions produced by an LLM."""
    provider: str = Field(..., description="AI Provider used (e.g., openrouter, ollama)")
    model: str = Field(..., description="Specific model tag (e.g., claude-3.5-sonnet)")
    validation_status: AIValidationStatus
    explanation: str = Field(..., description="Contextual explanation of the finding in this codebase")
    remediation_suggestion: str = Field(..., description="Recommended refactoring steps")
    unified_diff: Optional[str] = Field(default=None, description="Unified diff patch for remediation")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model self-reported confidence score")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    """An individual security, architectural, or quality defect found in the codebase."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique finding ID")
    rule_id: str = Field(..., description="Rule ID producing this finding")
    rule_name: str = Field(..., description="Descriptive name of the rule")
    category: FindingCategory
    evidence_type: EvidenceType
    severity: FindingSeverity
    confidence: FindingConfidence
    location: SourceLocation
    code_snippet: str = Field(..., min_length=1, description="Extract of relevant source code")
    description: str = Field(..., description="Specific description for this occurrence")
    remediation: str = Field(..., description="Default remediation advice")
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    ai_enrichment: Optional[AIFindingEnrichment] = Field(
        default=None,
        description="Supplemental AI enrichment; not the authoritative source of the finding"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("code_snippet")
    @classmethod
    def validate_code_snippet(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("code_snippet cannot be empty or only whitespace")
        return v
