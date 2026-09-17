"""Strongly typed models for dependency graphs, nodes, edges, and architecture metrics."""

from enum import Enum
from typing import Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class ImportType(str, Enum):
    """Classification of the import statement."""
    STATIC = "STATIC"        # Standard static import (e.g. import foo, from bar import baz)
    DYNAMIC = "DYNAMIC"      # Dynamic import (e.g. __import__, importlib.import_module, import())
    TYPE_ONLY = "TYPE_ONLY"  # Type-only import (e.g. import type { Foo } from 'bar')


class DependencyNode(BaseModel):
    """Represents a source file or module in the architecture graph."""
    id: str = Field(..., description="Unique module identifier (e.g. app.core.config)")
    file_path: str = Field(..., description="Repository-relative file path")
    module_name: str = Field(..., description="Dot-notated module name")
    language: str = Field(..., description="Source language (e.g. python, typescript)")
    loc: int = Field(default=0, ge=0, description="Lines of code")
    fan_in: int = Field(default=0, ge=0, description="Number of incoming dependencies (dependents)")
    fan_out: int = Field(default=0, ge=0, description="Number of outgoing dependencies")
    dependencies_count: int = Field(default=0, ge=0, description="Number of dependencies imported")
    dependents_count: int = Field(default=0, ge=0, description="Number of modules importing this")
    is_external: bool = Field(default=False, description="True if external library node")
    is_god_module: bool = Field(default=False, description="Flagged for excessively high fan-out / loc (Phase 3)")


class DependencyEdge(BaseModel):
    """Represents an import relationship between two modules."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique edge ID")
    source: str = Field(..., description="Source module ID that initiates the import")
    target: str = Field(..., description="Target module ID being imported")
    import_type: ImportType = Field(default=ImportType.STATIC)
    is_circular: bool = Field(default=False, description="True if part of a circular dependency cycle")
    is_external: bool = Field(default=False, description="True if target is an external dependency")
    dependency_category: str = Field(default="LOCAL", description="LOCAL, STDLIB, EXTERNAL, or UNRESOLVED")
    line_number: Optional[int] = Field(default=None, ge=1, description="Line number of import statement")

    @field_validator("target")
    @classmethod
    def validate_endpoints(cls, v: str, info) -> str:
        source = info.data.get("source")
        if source and source == v:
            # Self-import is allowed to be represented, marked as circular
            pass
        return v


class CircularDependency(BaseModel):
    """Represents a detected circular dependency cycle."""
    cycle_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique cycle ID")
    modules: list[str] = Field(..., min_length=2, description="Ordered list of module IDs forming the cycle")
    length: int = Field(..., ge=2, description="Number of modules participating in the cycle")


class CouplingMetrics(BaseModel):
    """Aggregate coupling and complexity metrics for the architecture graph."""
    total_modules: int = Field(default=0, ge=0)
    total_edges: int = Field(default=0, ge=0)
    density: float = Field(default=0.0, ge=0.0, le=1.0)
    average_fan_in: float = Field(default=0.0, ge=0.0)
    average_fan_out: float = Field(default=0.0, ge=0.0)
    max_fan_out: int = Field(default=0, ge=0)
    circular_cycles_count: int = Field(default=0, ge=0)


class ArchitectureGraph(BaseModel):
    """Complete graph topology and metrics of the audited codebase."""
    nodes: list[DependencyNode] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    circular_dependencies: list[CircularDependency] = Field(default_factory=list)
    metrics: CouplingMetrics = Field(default_factory=CouplingMetrics)
