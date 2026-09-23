"""SQLAlchemy model for AI enrichment records."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.finding import FindingSnapshot
    from backend.app.models.repository import Repository
    from backend.app.models.snapshot import AnalysisSnapshot


class AIEnrichmentRecord(Base):
    """Historical child record storing AI-assisted triage, explanations, and proposed diffs."""

    __tablename__ = "ai_enrichments"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Enrichment unique record UUID",
    )
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finding_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Target FindingSnapshot foreign key",
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Target AnalysisSnapshot foreign key",
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent Repository foreign key",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="QUEUED",
        index=True,
        doc="Enrichment lifecycle status: QUEUED, RUNNING, COMPLETED, FAILED, DISABLED",
    )
    provider: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="AI provider used for inference (openrouter, ollama)",
    )
    model: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Model identifier used for inference",
    )
    prompt_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="v1",
        doc="Version of prompt template and system directives",
    )

    # Advisory Analysis Results
    is_likely_true_positive: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Whether static finding was assessed as a genuine issue in context",
    )
    confidence_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        doc="Confidence score of the assessment (0.0 to 1.0)",
    )
    risk_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Executive summary of practical risk and blast radius",
    )
    technical_reasoning: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Detailed explanation of data flow, attack vectors, and defenses",
    )
    assumptions_limitations: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        doc="Contextual assumptions or limitations list",
    )
    prescribed_remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Prescriptive architectural or implementation advice",
    )
    proposed_patch: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        doc="Structured unified diff patch proposal dictionary",
    )
    raw_response: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        doc="Raw parsed response payload from provider for auditing",
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Error message if enrichment failed",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Creation timestamp in UTC",
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Completion or failure timestamp in UTC",
    )

    # Relationships
    finding: Mapped["FindingSnapshot"] = relationship(
        "FindingSnapshot",
        foreign_keys=[finding_id],
    )
    snapshot: Mapped["AnalysisSnapshot"] = relationship(
        "AnalysisSnapshot",
        foreign_keys=[snapshot_id],
    )
    repository: Mapped["Repository"] = relationship(
        "Repository",
        foreign_keys=[repository_id],
    )

    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "provider",
            "model",
            "prompt_version",
            name="uq_ai_enrichments_finding_model",
        ),
    )

    def __repr__(self) -> str:
        return f"<AIEnrichmentRecord(id='{self.id}', finding='{self.finding_id}', status='{self.status}', provider='{self.provider}')>"
