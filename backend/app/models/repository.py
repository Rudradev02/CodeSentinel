"""SQLAlchemy model for registered repositories."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.snapshot import AnalysisSnapshot


class Repository(Base):
    """Registered codebase repository available for static analysis and tracking."""

    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique repository UUID",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Display name of the repository",
    )
    path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        unique=True,
        index=True,
        doc="Validated absolute local filesystem path",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Registration timestamp in UTC",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Last metadata update timestamp in UTC",
    )

    # Relationships
    analyses: Mapped[list["AnalysisSnapshot"]] = relationship(
        "AnalysisSnapshot",
        back_populates="repository",
        cascade="all, delete-orphan",
        order_by="desc(AnalysisSnapshot.created_at)",
    )

    def __repr__(self) -> str:
        return f"<Repository(id='{self.id}', name='{self.name}', path='{self.path}')>"
