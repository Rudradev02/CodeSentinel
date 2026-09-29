"""SQLAlchemy model for enterprise organizations (Phase 28)."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.policy import CentralizedRulePack, CentralizedSuppression
    from backend.app.models.workspace import Workspace


class Organization(Base):
    """Enterprise organization grouping multi-repository workspaces and central governance policies."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique organization UUID",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Human-readable enterprise organization name",
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
        index=True,
        doc="URL-safe unique organizational identifier",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Organization creation timestamp in UTC",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Last metadata modification timestamp",
    )

    # Relationships
    workspaces: Mapped[list["Workspace"]] = relationship(
        "Workspace",
        back_populates="organization",
        cascade="all, delete-orphan",
        order_by="Workspace.name",
    )
    rule_packs: Mapped[list["CentralizedRulePack"]] = relationship(
        "CentralizedRulePack",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    suppressions: Mapped[list["CentralizedSuppression"]] = relationship(
        "CentralizedSuppression",
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Organization(id='{self.id}', slug='{self.slug}', name='{self.name}')>"
