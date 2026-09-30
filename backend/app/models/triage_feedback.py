"""SQLAlchemy models for Phase 30 AI intelligence records.

Stores human triage feedback, exploitability-based prioritizations,
advisory architectural refactoring proposals, and natural language policy candidates.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.finding import FindingSnapshot
    from backend.app.models.repository import Repository
    from backend.app.models.snapshot import AnalysisSnapshot


class FindingTriageFeedbackRecord(Base):
    """Stores human reviewer triage decisions used to train false-positive ML models."""

    __tablename__ = "finding_triage_feedbacks"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique feedback record UUID",
    )
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finding_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Target FindingSnapshot foreign key",
    )
    finding_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Content-addressable primary_hash of the finding",
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="AnalysisSnapshot foreign key",
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent Repository foreign key",
    )
    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Rule identifier (e.g. SEC-PY-005)",
    )
    label: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Triage verdict: TRUE_POSITIVE, FALSE_POSITIVE, ACCEPTED_RISK, SUSPECT_HEURISTIC",
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        doc="Human reviewer justification text",
    )
    reviewer_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Identity or email of reviewer",
    )
    feature_snapshot: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        doc="Extracted tabular features at triage time",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    finding: Mapped["FindingSnapshot"] = relationship("FindingSnapshot")
    snapshot: Mapped["AnalysisSnapshot"] = relationship("AnalysisSnapshot")
    repository: Mapped["Repository"] = relationship("Repository")


class AIPrioritizationRecord(Base):
    """Stores exploitability analysis and calculated priority score for a finding."""

    __tablename__ = "ai_prioritizations"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finding_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, doc="0.0 to 100.0 score")
    priority_band: Mapped[str] = mapped_column(String(16), nullable=False, doc="P0_IMMEDIATE to P3_LOW")
    exploitability_score: Mapped[float] = mapped_column(Float, nullable=False, doc="0.0 to 1.0 factor")
    contributing_factors: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    reasoning_summary: Mapped[str] = mapped_column(Text, nullable=False)
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AIRefactoringProposalRecord(Base):
    """Stores AI-generated architectural refactoring proposals with simulated impact."""

    __tablename__ = "ai_refactoring_proposals"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_finding_ids: Mapped[Optional[list[str]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    refactoring_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    problem_statement: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_design: Mapped[str] = mapped_column(Text, nullable=False)
    affected_components: Mapped[Optional[list[str]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    affected_files: Mapped[Optional[list[str]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    hypothetical_edge_mutations: Mapped[Optional[list[dict[str, str]]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    simulated_metric_deltas: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    simulation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PROPOSAL_ONLY",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PROPOSAL_ONLY",
    )
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AIPolicyProposalRecord(Base):
    """Stores natural language policy draft candidates and validation states."""

    __tablename__ = "ai_policy_proposals"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    policy_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    natural_language_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    generated_policy_json: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
    )
    validation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="VALIDATED_CANDIDATE",
    )
    validation_diagnostics: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    author_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
