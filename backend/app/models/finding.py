"""SQLAlchemy model for finding snapshots."""

from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.snapshot import AnalysisSnapshot


class FindingSnapshot(Base):
    """Immutable snapshot record of an individual finding in an analysis run."""

    __tablename__ = "finding_snapshots"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Internal primary key UUID",
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Reference to parent analysis snapshot",
    )
    finding_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        doc="Original canonical/deterministic finding UUID from analyzer",
    )
    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Rule identifier (e.g. SEC-PY-001, ARC-001)",
    )
    rule_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Human-readable rule name",
    )
    category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Category: SECURITY or ARCHITECTURE",
    )
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="Severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO",
    )
    confidence: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="Confidence: HIGH, MEDIUM, or LOW",
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Summary message headline",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Detailed explanation of the issue",
    )
    remediation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Prescriptive remediation guidance",
    )

    # Source code physical coordinates
    file_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        doc="Repository-relative file path",
    )
    line_start: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        doc="Starting line number (1-indexed)",
    )
    line_end: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Ending line number (1-indexed)",
    )
    column_start: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Starting column offset",
    )
    column_end: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Ending column offset",
    )

    # Evidence snippet and highlighting
    snippet: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Source snippet extract (with secrets redacted if sensitive)",
    )
    language: Mapped[str] = mapped_column(
        String(32),
        default="plaintext",
        nullable=False,
        doc="Language syntax highlighting mode for code viewer",
    )
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Structured evidence payload from rule execution",
    )

    # Classification tags
    cwe_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ai_validation_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Relationship to snapshot
    snapshot: Mapped["AnalysisSnapshot"] = relationship("AnalysisSnapshot", back_populates="findings")

    def __repr__(self) -> str:
        return f"<FindingSnapshot(rule='{self.rule_id}', file='{self.file_path}:{self.line_start}')>"
