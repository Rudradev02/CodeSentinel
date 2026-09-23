"""Pydantic schemas for analysis jobs and SSE progress events."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalysisJobDTO(BaseModel):
    """Public representation of an asynchronous analysis job."""

    id: str = Field(..., description="Unique analysis job UUID")
    repository_id: str = Field(..., description="Parent repository UUID")
    status: str = Field(..., description="Job status: QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED")
    snapshot_id: Optional[str] = Field(None, description="Resulting AnalysisSnapshot UUID if completed")
    created_at: datetime = Field(..., description="Job creation timestamp in UTC")
    started_at: Optional[datetime] = Field(None, description="Worker start timestamp in UTC")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp in UTC")
    progress_percent: int = Field(0, description="Analysis progress (0-100)")
    progress_stage: Optional[str] = Field(None, description="Current pipeline stage name")
    progress_message: Optional[str] = Field(None, description="Human-readable progress description")
    error_message: Optional[str] = Field(None, description="Error message if analysis failed")
    stream_url: str = Field(..., description="Server-Sent Events endpoint URL for progress streaming")
    configuration: Optional[dict[str, Any]] = Field(None, description="Analysis configuration used")

    model_config = ConfigDict(from_attributes=True)


class JobListResponse(BaseModel):
    """Paginated list of analysis jobs."""

    items: list[AnalysisJobDTO]
    total: int
    skip: int
    limit: int


class SSEProgressEvent(BaseModel):
    """Structured event payload streamed over SSE."""

    job_id: str
    status: str
    progress_percent: int
    progress_stage: Optional[str] = None
    progress_message: Optional[str] = None
    snapshot_id: Optional[str] = None
    error_message: Optional[str] = None
