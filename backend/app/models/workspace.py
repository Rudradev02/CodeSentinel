"""SQLAlchemy models for multi-repository workspaces and workspace snapshots (Phase 28)."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.organization import Organization
    from backend.app.models.repository import Repository
    from backend.app.models.snapshot import AnalysisSnapshot


class WorkspaceRepository(Base):
    """Many-to-many association mapping repositories to workspaces with roles and dependencies."""

    __tablename__ = "workspace_repositories"

    workspace_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        primary_key=True,
    )
    repository_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        default="INTERNAL_SERVICE",
        nullable=False,
        doc="Architectural tier: PUBLIC_ENTRYPOINT, INTERNAL_SERVICE, INTERNAL_LIBRARY, DATA_LAYER, BATCH_WORKER",
    )
    criticality: Mapped[str] = mapped_column(
        String(16),
        default="MEDIUM",
        nullable=False,
        doc="Severity weighting: CRITICAL, HIGH, MEDIUM, LOW",
    )
    depends_on: Mapped[Optional[list[str]]] = mapped_column(
        JSON,
        default=list,
        nullable=True,
        doc="List of repository IDs this repository depends on within the workspace",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="repository_links")
    repository: Mapped["Repository"] = relationship("Repository")


class Workspace(Base):
    """Logical cluster of collaborating repositories forming an interconnected software system."""

    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique workspace UUID",
    )
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent organization UUID",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Human-readable workspace display name",
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="URL-safe workspace identifier within the organization",
    )
    manifest_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        doc="Absolute path to workspace manifest YAML file",
    )
    config_payload: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Parsed workspace configuration overrides and shared policies",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Workspace creation timestamp in UTC",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="Last metadata modification timestamp",
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="workspaces")
    repository_links: Mapped[list["WorkspaceRepository"]] = relationship(
        "WorkspaceRepository",
        back_populates="workspace",
        cascade="all, delete-orphan",
    )
    snapshots: Mapped[list["WorkspaceSnapshot"]] = relationship(
        "WorkspaceSnapshot",
        back_populates="workspace",
        cascade="all, delete-orphan",
        order_by="desc(WorkspaceSnapshot.created_at)",
    )

    def __repr__(self) -> str:
        return f"<Workspace(id='{self.id}', org='{self.organization_id}', slug='{self.slug}')>"


class WorkspaceSnapshot(Base):
    """Immutable composite snapshot capturing a completed multi-repository workspace analysis run."""

    __tablename__ = "workspace_snapshots"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique workspace analysis snapshot UUID",
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent workspace UUID",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        doc="Execution completion timestamp in UTC",
    )
    composite_health_score: Mapped[float] = mapped_column(
        Float,
        default=100.0,
        nullable=False,
        doc="Weighted composite health score (0.0 to 100.0) across all member repositories",
    )
    composite_grade: Mapped[str] = mapped_column(
        String(8),
        default="A",
        nullable=False,
        doc="Overall composite letter grade: A, B, C, D, or F",
    )
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    merkle_workspace_root: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Merkle-of-Merkles root digest combining all constituent repository finding roots",
    )
    attestation_envelope: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Composite in-toto v1.0 DSSE attestation envelope for the workspace release",
    )
    compliance_suite: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Fleet-wide multi-framework compliance evaluation rollup",
    )
    repository_snapshot_ids: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        doc="List of individual AnalysisSnapshot UUIDs included in this workspace run",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="snapshots")
    member_snapshots: Mapped[list["AnalysisSnapshot"]] = relationship(
        "AnalysisSnapshot",
        back_populates="workspace_snapshot",
    )

    def __repr__(self) -> str:
        return f"<WorkspaceSnapshot(id='{self.id}', workspace='{self.workspace_id}', score={self.composite_health_score})>"
