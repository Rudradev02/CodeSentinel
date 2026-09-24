"""Pydantic schemas for Phase 15 Call Graph Intelligence."""

from typing import Optional
from pydantic import BaseModel, Field


class CallGraphSummaryDTO(BaseModel):
    """Call graph analysis metrics and summary for a snapshot."""

    analysis_id: str = Field(..., description="Unique analysis snapshot ID")
    total_functions: int = Field(default=0, ge=0, description="Total functions discovered")
    total_call_edges: int = Field(default=0, ge=0, description="Total call sites evaluated")
    resolved_local: int = Field(default=0, ge=0, description="Edges resolved within same file")
    resolved_import: int = Field(default=0, ge=0, description="Edges resolved across imports")
    unresolved: int = Field(default=0, ge=0, description="External or unresolved call edges")
    resolution_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of resolved calls")
    summarized_functions: int = Field(default=0, ge=0, description="Functions with generated summaries")
    unsummarized_functions: int = Field(default=0, ge=0, description="Functions exceeding bounds or skipped")
    interprocedural_findings_count: int = Field(default=0, ge=0, description="Findings discovered via cross-function taint")
    max_call_depth_reached: int = Field(default=0, ge=0, description="Max call depth reached in propagation")
