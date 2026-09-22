"""SQLAlchemy model for health deduction snapshots."""

from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.snapshot import AnalysisSnapshot


class HealthDeductionSnapshot(Base):
    """Immutable record of an individual health deduction item."""

    __tablename__ = "health_deduction_snapshots"

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
    category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Sub-score category: SECURITY or ARCHITECTURE",
    )
    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Rule ID causing the deduction",
    )
    points_deducted: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        doc="Number of points deducted from base 100",
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Human-readable reason for the penalty",
    )
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        doc="UUID of originating finding if tied directly to one",
    )
    item_count: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        doc="Number of occurrences or items contributing to deduction",
    )

    # Relationship to snapshot
    snapshot: Mapped["AnalysisSnapshot"] = relationship("AnalysisSnapshot", back_populates="deductions")

    def __repr__(self) -> str:
        return f"<HealthDeductionSnapshot(rule='{self.rule_id}', points={self.points_deducted})>"
