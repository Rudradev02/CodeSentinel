"""Top-level structured AnalysisResult schema for CodeSentinel."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid
from pydantic import BaseModel, Field

from analyzer.models.findings import Finding
from analyzer.models.graph import ArchitectureGraph
from analyzer.models.metadata import DiscoveredFileMetadata, FrameworkEvidence, ParsingError


class AnalysisStatus(str, Enum):
    """Lifecycle status of an analysis run."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RepositoryInfo(BaseModel):
    """High-level repository metadata discovered during ingestion."""
    name: str = Field(..., description="Repository or root directory name")
    local_path: str = Field(..., description="Absolute local filesystem path")
    commit_hash: Optional[str] = Field(default=None, description="Git commit SHA if available")
    branch: Optional[str] = Field(default=None, description="Active branch name if available")
    detected_languages: dict[str, int] = Field(
        default_factory=dict,
        description="Map of language names to file counts (e.g. {'Python': 40, 'TypeScript': 60})"
    )
    detected_frameworks: list[str] = Field(
        default_factory=list,
        description="Detected frameworks (e.g. ['Django', 'React'])"
    )
    total_files: int = Field(default=0, ge=0, description="Total source files discovered")
    total_loc: int = Field(default=0, ge=0, description="Total lines of code analyzed")


class SecuritySummary(BaseModel):
    """Aggregated counters for security findings."""
    total: int = Field(default=0, ge=0)
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    deterministic_count: int = Field(default=0, ge=0)
    heuristic_count: int = Field(default=0, ge=0)
    ai_enriched_count: int = Field(default=0, ge=0)


class ArchitectureSummary(BaseModel):
    """Aggregated counters for architectural health."""
    total_modules: int = Field(default=0, ge=0)
    circular_dependencies_count: int = Field(default=0, ge=0)
    god_modules_count: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)


class AnalysisMetadata(BaseModel):
    """Operational metadata regarding the analysis run."""
    engine_version: str = Field(default="0.1.0")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = Field(default=None, ge=0.0)


class DependencyDiagnostic(BaseModel):
    """Structured diagnostic record for dependency resolution issues (Phase 6)."""
    file_path: str = Field(..., description="Repository-relative path of the importing file")
    source_module: str = Field(..., description="Raw import module string")
    line_number: Optional[int] = Field(default=None, ge=1, description="Line number of the import statement")
    diagnostic_type: str = Field(..., description="Diagnostic category (e.g., UNRESOLVED_LOCAL_IMPORT, UNRESOLVED_ALIAS_TARGET)")
    message: str = Field(..., description="Human-readable diagnostic message")
    reason: str = Field(..., description="Technical reason for the diagnostic")
    assigned_category: str = Field(default="UNRESOLVED", description="Final dependency category assigned")


class AnalysisResult(BaseModel):
    """Canonical, strongly-typed result produced by the CodeSentinel analyzer engine."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique analysis run ID")
    status: AnalysisStatus = Field(default=AnalysisStatus.COMPLETED)
    repository: RepositoryInfo
    metadata: AnalysisMetadata = Field(default_factory=AnalysisMetadata)
    security_summary: SecuritySummary = Field(default_factory=SecuritySummary)
    architecture_summary: ArchitectureSummary = Field(default_factory=ArchitectureSummary)
    security_findings: list[Finding] = Field(default_factory=list)
    architecture_findings: list[Finding] = Field(default_factory=list)
    graph: ArchitectureGraph = Field(default_factory=ArchitectureGraph)
    # Phase 2 enriched data
    files: list[DiscoveredFileMetadata] = Field(default_factory=list, description="Discovered source file catalog")
    framework_details: list[FrameworkEvidence] = Field(default_factory=list, description="Evidence-backed framework detections")
    parsing_errors: list[ParsingError] = Field(default_factory=list, description="Non-fatal errors encountered during parsing")
    # Phase 6: Structured dependency resolution diagnostics
    dependency_diagnostics: list[DependencyDiagnostic] = Field(default_factory=list, description="Dependency resolution diagnostic records")
    error_message: Optional[str] = None
