"""Analysis request and response DTO schemas."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Request payload to initiate a synchronous codebase analysis."""

    path: str = Field(
        ...,
        description="Local repository directory path to analyze",
        examples=["tests/fixtures/sample_project"],
    )
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


class LocationDTO(BaseModel):
    """Source code coordinates for a finding."""

    file_path: str = Field(..., description="Repository-relative file path")
    line_start: int = Field(..., ge=1, description="Starting line (1-indexed)")
    line_end: Optional[int] = Field(default=None, ge=1, description="Ending line (1-indexed)")
    column_start: Optional[int] = Field(default=None, ge=0, description="Starting column offset")
    column_end: Optional[int] = Field(default=None, ge=0, description="Ending column offset")


class EvidenceDTO(BaseModel):
    """Bounded code snippet and syntax information for Monaco preview."""

    snippet: str = Field(..., description="Target source extract")
    language: str = Field(default="plaintext", description="Language mode for syntax coloring")
    highlight_lines: list[int] = Field(default_factory=list, description="1-indexed line numbers to highlight")


class FindingDTO(BaseModel):
    """Normalized finding representation for API responses."""

    id: str = Field(..., description="Unique deterministic or random UUID")
    rule_id: str = Field(..., description="Originating rule identifier")
    rule_name: str = Field(..., description="Descriptive title of the rule")
    message: str = Field(..., description="Summary headline of the finding")
    category: str = Field(..., description="SECURITY or ARCHITECTURE")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence: str = Field(..., description="HIGH, MEDIUM, LOW")
    description: str = Field(..., description="Contextual explanation")
    remediation: str = Field(..., description="Remediation steps")
    location: LocationDTO = Field(..., description="Physical coordinates in repository")
    evidence: EvidenceDTO = Field(..., description="Source snippet extract for viewer")
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    dataflow_evidence: Optional[dict[str, Any]] = Field(default=None, description="Intraprocedural taint flow trace if applicable")


class ComponentCouplingDTO(BaseModel):
    """Afferent, efferent, and instability metrics for a component."""

    afferent: int = Field(..., ge=0, description="Ca: Number of external components importing this component")
    efferent: int = Field(..., ge=0, description="Ce: Number of external components imported by this component")
    instability: float = Field(..., ge=0.0, le=1.0, description="Instability metric I = Ce / (Ca + Ce)")
    total_loc: int = Field(default=0, ge=0, description="Total lines of code in component")
    file_count: int = Field(default=0, ge=0, description="Total files in component")
    betweenness_centrality: float = Field(default=0.0, ge=0.0, description="Betweenness centrality in local component graph")
    in_degree_centrality: float = Field(default=0.0, ge=0.0, description="In-degree centrality")
    out_degree_centrality: float = Field(default=0.0, ge=0.0, description="Out-degree centrality")


class ComponentNodeDTO(BaseModel):
    """Component node in the subsystem architecture graph."""

    id: str = Field(..., description="Normalized dot-separated component identifier")
    name: str = Field(..., description="Display name of the component")
    path: str = Field(..., description="Repository-relative directory path")
    layer: Optional[str] = Field(default=None, description="Inferred architectural tier")
    coupling: ComponentCouplingDTO = Field(..., description="Coupling and stability metrics")
    files: list[str] = Field(default_factory=list, description="File paths in component")


class ComponentEdgeDTO(BaseModel):
    """Directed dependency edge between two components."""

    id: str = Field(..., description="Unique edge identifier")
    source: str = Field(..., description="Source component ID")
    target: str = Field(..., description="Target component ID")
    weight: int = Field(default=1, ge=1, description="Underlying file dependency count")
    is_cycle: bool = Field(default=False, description="True if part of a circular component cycle")


class ComponentGraphDTO(BaseModel):
    """Subsystem-level component graph topology."""

    nodes: list[ComponentNodeDTO] = Field(default_factory=list)
    edges: list[ComponentEdgeDTO] = Field(default_factory=list)
    circular_components_count: int = Field(default=0, ge=0)
    cycles: list[list[str]] = Field(default_factory=list, description="Component-level SCC cycles")


class DeductionDTO(BaseModel):
    """Itemized score deduction from codebase health."""

    category: str = Field(..., description="SECURITY or ARCHITECTURE")
    rule_id: str = Field(..., description="Originating rule ID")
    points_deducted: float = Field(..., ge=0.0, description="Deducted points")
    reason: str = Field(..., description="Reason for the penalty")
    finding_id: Optional[str] = None
    item_count: int = Field(default=1, ge=1)


class SubScoreDTO(BaseModel):
    """Categorical sub-score (Architecture Health or Security Posture)."""

    score: float = Field(..., ge=0.0, le=100.0)
    grade: str = Field(..., description="Letter grade: A, B, C, D, F")
    deductions: list[DeductionDTO] = Field(default_factory=list)


class HealthScoreDTO(BaseModel):
    """Authoritative Phase 7 Codebase Health score."""

    overall_score: float = Field(..., ge=0.0, le=100.0)
    overall_grade: str = Field(..., description="Overall letter grade: A, B, C, D, F")
    architecture_health: SubScoreDTO
    security_posture: SubScoreDTO
    total_deductions_count: int = Field(default=0, ge=0)
    summary: Optional[str] = None


class AnalysisSummaryDTO(BaseModel):
    """High-level counters and operational execution metrics."""

    total_findings: int = Field(default=0, ge=0)
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    total_modules: int = Field(default=0, ge=0)
    circular_dependencies_count: int = Field(default=0, ge=0)
    total_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0.0)


class DiagnosticDTO(BaseModel):
    """Dependency resolution diagnostic record."""

    file_path: str
    source_module: str
    line_number: Optional[int] = None
    diagnostic_type: str
    message: str
    reason: str
    assigned_category: str


class AnalysisResultDTO(BaseModel):
    """Complete canonical analysis result payload."""

    id: str = Field(..., description="Unique analysis run identifier")
    status: str = Field(default="COMPLETED")
    repository_path: str = Field(..., description="Absolute analyzed path")
    repository_name: str = Field(..., description="Display name of repository")
    summary: AnalysisSummaryDTO = Field(..., description="Aggregated counters")
    health: Optional[HealthScoreDTO] = Field(default=None, description="Phase 7 health evaluation")
    findings: list[FindingDTO] = Field(default_factory=list, description="Ordered finding records")
    component_graph: Optional[ComponentGraphDTO] = Field(default=None, description="Subsystem component graph")
    diagnostics: list[DiagnosticDTO] = Field(default_factory=list, description="Resolution diagnostics")
