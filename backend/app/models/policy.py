"""SQLAlchemy models for centralized organizational rule packs and enterprise suppressions (Phase 28)."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.organization import Organization


class CentralizedRulePack(Base):
    """Centrally registered enterprise rule pack distributed across organization repositories."""

    __tablename__ = "centralized_rule_packs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique record UUID",
    )
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent organization UUID",
    )
    pack_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Rule pack identifier (e.g. org-enterprise-baseline)",
    )
    version: Mapped[str] = mapped_column(
        String(32),
        default="1.0.0",
        nullable=False,
        doc="Semantic version string",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Human-readable rule pack title",
    )
    pack_yaml: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Raw YAML definition of the rule pack",
    )
    pack_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Canonical SHA-256 digest of the resolved rule pack state",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="rule_packs")

    def __repr__(self) -> str:
        return f"<CentralizedRulePack(org='{self.organization_id}', pack='{self.pack_id}', v='{self.version}')>"


class CentralizedSuppression(BaseModel := Base):
    """Authorized enterprise suppression exception managed at organization scale."""

    __tablename__ = "centralized_suppressions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique suppression UUID",
    )
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent organization UUID",
    )
    rule_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="Target rule ID being suppressed (e.g. SEC-PY-001)",
    )
    target_repo_id: Mapped[str] = mapped_column(
        String(36),
        default="*",
        nullable=False,
        doc="Specific repository ID or wildcard '*' for all org repos",
    )
    target_file_pattern: Mapped[str] = mapped_column(
        String(255),
        default="*",
        nullable=False,
        doc="Glob pattern matching file path relative to repo root",
    )
    fingerprint_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Optional primary hash of FindingFingerprint for exact occurrence suppression",
    )
    justification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Auditor / security team justification for the exemption",
    )
    compensating_control: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Description of compensating security safeguards satisfying regulatory intent",
    )
    approved_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Identifier / email of the authorized security reviewer",
    )
    ticket_reference: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Auditable ticketing reference (e.g. JIRA-4219)",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        doc="Mandatory expiration timestamp; expired suppressions revert finding to ACTIVE",
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="suppressions")

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def __repr__(self) -> str:
        return f"<CentralizedSuppression(id='{self.id}', rule='{self.rule_id}', repo='{self.target_repo_id}')>"
