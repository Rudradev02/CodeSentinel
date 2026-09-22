"""SQLAlchemy model for immutable analysis snapshots."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.component import ComponentEdgeSnapshot, ComponentSnapshot
    from backend.app.models.finding import FindingSnapshot
    from backend.app.models.health import HealthDeductionSnapshot
    from backend.app.models.repository import Repository


class AnalysisSnapshot(Base):
    """Immutable record of a completed static analysis run on a repository."""

    __tablename__ = "analysis_snapshots"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        doc="Analysis run UUID (matches canonical AnalysisResult.id)",
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Foreign key pointing to the target repository",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        doc="Execution completion timestamp in UTC",
    )

    # Git metadata (local static provenance)
    commit_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Git commit hash at analysis time if in a git repo",
    )
    branch: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Git branch name at analysis time",
    )
    is_dirty: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Whether local working tree contained uncommitted changes",
    )

    # Operational metrics
    analyzer_version: Mapped[str] = mapped_column(
        String(32),
        default="0.1.0",
        nullable=False,
        doc="Version of analyzer engine used",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="COMPLETED",
        nullable=False,
        doc="Analysis execution status",
    )
    duration_seconds: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        doc="Static analysis execution time in seconds",
    )
    total_files: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Total source files discovered and analyzed",
    )
    total_loc: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Total lines of code scanned",
    )

    # Serialized analysis configuration at run time
    configuration: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Analysis configuration parameters applied",
    )

    # Deterministic Health Scoring (Phase 7 canonical model)
    overall_score: Mapped[float] = mapped_column(
        Float,
        default=100.0,
        nullable=False,
        doc="Composite health score (0.0 to 100.0)",
    )
    overall_grade: Mapped[str] = mapped_column(
        String(8),
        default="A",
        nullable=False,
        doc="Letter grade: A, B, C, D, or F",
    )
    architecture_score: Mapped[float] = mapped_column(
        Float,
        default=100.0,
        nullable=False,
        doc="Architecture health sub-score (0.0 to 100.0)",
    )
    architecture_grade: Mapped[str] = mapped_column(
        String(8),
        default="A",
        nullable=False,
        doc="Architecture health letter grade",
    )
    security_score: Mapped[float] = mapped_column(
        Float,
        default=100.0,
        nullable=False,
        doc="Security posture sub-score (0.0 to 100.0)",
    )
    security_grade: Mapped[str] = mapped_column(
        String(8),
        default="A",
        nullable=False,
        doc="Security posture letter grade",
    )
    total_deductions_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Total count of health deductions applied",
    )
    health_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="One-sentence health summary statement",
    )

    # Finding counters
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Topology metrics
    circular_dependencies_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    circular_components_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Diagnostics & extra metadata
    diagnostics_payload: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Serialized dependency resolution diagnostics",
    )

    # Relationships
    repository: Mapped["Repository"] = relationship("Repository", back_populates="analyses")
    findings: Mapped[list["FindingSnapshot"]] = relationship(
        "FindingSnapshot",
        back_populates="snapshot",
        cascade="all, delete-orphan",
        order_by="FindingSnapshot.line_start",
    )
    deductions: Mapped[list["HealthDeductionSnapshot"]] = relationship(
        "HealthDeductionSnapshot",
        back_populates="snapshot",
        cascade="all, delete-orphan",
    )
    components: Mapped[list["ComponentSnapshot"]] = relationship(
        "ComponentSnapshot",
        back_populates="snapshot",
        cascade="all, delete-orphan",
    )
    component_edges: Mapped[list["ComponentEdgeSnapshot"]] = relationship(
        "ComponentEdgeSnapshot",
        back_populates="snapshot",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AnalysisSnapshot(id='{self.id}', repo='{self.repository_id}', score={self.overall_score})>"
