"""Metadata models for discovered files, framework evidence, and parser error logging."""

from typing import Optional
from pydantic import BaseModel, Field


class DiscoveredFileMetadata(BaseModel):
    """Metadata for a source file discovered during repository ingestion."""
    path: str = Field(..., description="Absolute path on disk")
    relative_path: str = Field(..., description="Normalized path relative to repository root")
    extension: str = Field(..., description="File extension including dot (e.g. .py, .tsx)")
    language: str = Field(..., description="Detected language identifier")
    size_bytes: int = Field(default=0, ge=0, description="File size in bytes")
    line_count: int = Field(default=0, ge=0, description="Number of lines in the file")


class FrameworkEvidence(BaseModel):
    """Evidence and confidence score for a detected web framework."""
    framework: str = Field(..., description="Framework identifier (e.g. django, flask, react)")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score representing evidence strength, not absolute certainty"
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="List of verifiable facts supporting detection"
    )


class ParsingError(BaseModel):
    """Structural log of a parsing issue encountered on a file."""
    file_path: str = Field(..., description="Repository-relative path of the failing file")
    error_message: str = Field(..., description="Sanitized parser error description")
    line_number: Optional[int] = Field(default=None, ge=1)
    column_number: Optional[int] = Field(default=None, ge=0)
