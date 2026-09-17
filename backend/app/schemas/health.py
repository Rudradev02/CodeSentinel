"""Health check schema definitions for CodeSentinel Backend."""

from datetime import datetime
from typing import Dict
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Schema representing backend health and readiness."""

    status: str = Field(default="healthy", description="Overall operational health status")
    service: str = Field(default="CodeSentinel API", description="Service identifier")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Runtime environment (development, staging, production)")
    uptime_seconds: float = Field(..., ge=0.0, description="Seconds since backend application startup")
    timestamp: datetime = Field(..., description="Timestamp of health check evaluation")
    components: Dict[str, str] = Field(
        ...,
        description="Granular health states of subsystem components. Only active subsystems are reported as healthy."
    )
