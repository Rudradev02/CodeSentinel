"""SQLAlchemy models for component graph nodes and edges snapshots."""

from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import Boolean, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.models.snapshot import AnalysisSnapshot


class ComponentSnapshot(Base):
    """Immutable record of an architectural component node at analysis time."""

    __tablename__ = "component_snapshots"

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
    component_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Normalized dot-separated component identifier (e.g. backend.app.api)",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Short display name of the component",
    )
    path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        doc="Repository-relative directory path",
    )
    layer: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Inferred architectural tier (e.g. Presentation, Domain, Infrastructure)",
    )
    afferent_coupling: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Ca: Number of external components importing this component",
    )
    efferent_coupling: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Ce: Number of external components imported by this component",
    )
    instability: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        doc="Instability metric I = Ce / (Ca + Ce)",
    )
    total_loc: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Total lines of code in component",
    )
    file_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Total file count in component",
    )
    betweenness_centrality: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        doc="Betweenness centrality in local component graph",
    )
    in_degree_centrality: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        doc="Normalized incoming edge centrality",
    )
    out_degree_centrality: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        doc="Normalized outgoing edge centrality",
    )
    files: Mapped[Optional[list[str]]] = mapped_column(
        JSON,
        nullable=True,
        doc="List of repository-relative file paths in this component",
    )

    # Relationship to snapshot
    snapshot: Mapped["AnalysisSnapshot"] = relationship("AnalysisSnapshot", back_populates="components")

    def __repr__(self) -> str:
        return f"<ComponentSnapshot(id='{self.component_id}', layer='{self.layer}')>"


class ComponentEdgeSnapshot(Base):
    """Immutable record of a directed dependency edge between components."""

    __tablename__ = "component_edge_snapshots"

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
    edge_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Unique edge identifier (e.g. source->target)",
    )
    source_component_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Source component ID",
    )
    target_component_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Target component ID",
    )
    weight: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        doc="Underlying file dependency count",
    )
    is_circular: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="True if edge forms part of a circular component cycle",
    )

    # Relationship to snapshot
    snapshot: Mapped["AnalysisSnapshot"] = relationship("AnalysisSnapshot", back_populates="component_edges")

    def __repr__(self) -> str:
        return f"<ComponentEdgeSnapshot(src='{self.source_component_id}', dst='{self.target_component_id}')>"
