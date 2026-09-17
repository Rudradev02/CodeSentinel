"""Strongly-typed findings and classification models for CodeSentinel."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
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
    """Precise source code coordinate for a finding.
    
    Supports both primary coordinate field names (file_path, line_start, line_end, col_start, col_end)
    and ergonomic aliases (file, start_line, end_line, start_column, end_column).
    If end coordinates cannot be determined reliably, end_line and end_column default to None.
    """
    file_path: str = Field(..., description="Path to file relative to repository root")
    line_start: int = Field(..., ge=1, description="Starting line number (1-indexed)")
    line_end: Optional[int] = Field(default=None, ge=1, description="Ending line number (1-indexed), or None if unavailable")
    col_start: Optional[int] = Field(default=None, ge=0, description="Starting column offset")
    col_end: Optional[int] = Field(default=None, ge=0, description="Ending column offset, or None if unavailable")

    # Standard coordinate field aliases for serialization & direct access
    start_line: Optional[int] = Field(default=None, ge=1)
    start_column: Optional[int] = Field(default=None, ge=0)
    end_line: Optional[int] = Field(default=None, ge=1)
    end_column: Optional[int] = Field(default=None, ge=0)

    @model_validator(mode="before")
    @classmethod
    def reconcile_coordinate_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "file" in data and "file_path" not in data:
                data["file_path"] = data["file"]
            elif "file_path" in data and "file" not in data:
                data["file"] = data["file_path"]

            if "start_line" in data and "line_start" not in data:
                data["line_start"] = data["start_line"]
            if "start_column" in data and "col_start" not in data:
                data["col_start"] = data["start_column"]
            if "end_line" in data and "line_end" not in data:
                data["line_end"] = data["end_line"]
            if "end_column" in data and "col_end" not in data:
                data["col_end"] = data["end_column"]
        return data

    @model_validator(mode="after")
    def validate_and_sync_coordinates(self) -> "SourceLocation":
        if self.start_line is None:
            self.start_line = self.line_start
        if self.start_column is None:
            self.start_column = self.col_start
        if self.end_line is None:
            self.end_line = self.line_end
        if self.end_column is None:
            self.end_column = self.col_end

        if self.line_end is not None and self.line_start > self.line_end:
            raise ValueError(f"line_start ({self.line_start}) cannot exceed line_end ({self.line_end})")
        return self

    @property
    def file(self) -> str:
        return self.file_path


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

    # Phase 5 metadata enhancements
    rationale: Optional[str] = Field(default=None, description="Architectural or security justification for why this rule matters")
    supported_languages: list[str] = Field(default_factory=list, description="Languages evaluated by this rule")

    @model_validator(mode="after")
    def sync_metadata_fields(self) -> "RuleDefinition":
        if not self.supported_languages and self.languages:
            self.supported_languages = list(self.languages)
        elif not self.languages and self.supported_languages:
            self.languages = list(self.supported_languages)
        return self

    @property
    def id(self) -> str:
        return self.rule_id


RuleMetadata = RuleDefinition


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
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp if set by storage/persistence layer")

    # Phase 5 enhancements
    message: Optional[str] = Field(default=None, description="Concise headline summary of the detected pattern")
    explanation: Optional[str] = Field(default=None, description="Contextual explanation of why this finding represents a risk")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Structured factual evidence observed by the static analyzer")
    file: Optional[str] = Field(default=None, description="Repository-relative file path")
    title: Optional[str] = Field(default=None, description="Descriptive title of the finding (alias for rule_name)")

    @field_validator("code_snippet")
    @classmethod
    def validate_code_snippet(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("code_snippet cannot be empty or only whitespace")
        return v

    @model_validator(mode="after")
    def sync_enhanced_fields(self) -> "Finding":
        if self.file is None:
            self.file = self.location.file_path
        if self.title is None:
            self.title = self.rule_name
        if self.message is None:
            self.message = self.rule_name
        if self.explanation is None:
            self.explanation = self.description
        return self

    @property
    def start_line(self) -> int:
        return self.location.line_start

    @property
    def start_column(self) -> Optional[int]:
        return self.location.col_start

    @property
    def end_line(self) -> Optional[int]:
        return self.location.line_end

    @property
    def end_column(self) -> Optional[int]:
        return self.location.col_end

