"""Structured error response schemas for CodeSentinel API."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class APIErrorResponse(BaseModel):
    """Standard error response payload for API errors."""

    code: str = Field(
        ...,
        description="Machine-readable error identifier (e.g. NOT_FOUND, INVALID_PATH, SECURITY_POLICY_VIOLATION)",
    )
    message: str = Field(
        ...,
        description="Human-readable summary of the error",
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Structured contextual error details",
    )
