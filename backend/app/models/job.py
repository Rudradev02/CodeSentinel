"""SQLAlchemy model for asynchronous analysis task jobs."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.repository import Repository
    from backend.app.models.snapshot import AnalysisSnapshot


class AnalysisJob(Base):
    """Tracks asynchronous analysis execution lifecycle and progress."""

    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique analysis job UUID",
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent repository UUID",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="QUEUED",
        index=True,
        doc="Job execution status: QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED",
    )
    celery_task_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Internal Celery worker task ID (backend-only, not exposed in public DTOs)",
    )
    snapshot_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Resulting immutable AnalysisSnapshot UUID upon completion",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Job creation timestamp in UTC",
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp when analysis worker started processing",
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp when analysis job reached a terminal state",
    )
    progress_percent: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Current progress percentage (0-100)",
    )
    progress_stage: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Current pipeline stage name (e.g. INGESTION, PARSING, RULES)",
    )
    progress_message: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        doc="Human-readable progress description",
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Detailed error message if the job failed or was aborted",
    )
    configuration: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        doc="Analysis configuration parameters passed to the engine",
    )

    # Relationships
    repository: Mapped["Repository"] = relationship(
        "Repository",
        back_populates="jobs",
    )
    snapshot: Mapped[Optional["AnalysisSnapshot"]] = relationship(
        "AnalysisSnapshot",
    )

    def __repr__(self) -> str:
        return f"<AnalysisJob(id='{self.id}', repo='{self.repository_id}', status='{self.status}', progress={self.progress_percent}%)>"
