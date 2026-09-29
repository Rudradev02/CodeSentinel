"""Strongly-typed models for multi-repository workspace orchestration (Phase 28)."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml

from analyzer.models.findings import FindingSeverity


class WorkspaceRole(str, Enum):
    """Architectural classification of a repository within a workspace fleet."""
    PUBLIC_ENTRYPOINT = "PUBLIC_ENTRYPOINT"   # Ingress API gateway, web frontend, public HTTP controller
    INTERNAL_SERVICE = "INTERNAL_SERVICE"     # Downstream microservice, internal RPC provider
    INTERNAL_LIBRARY = "INTERNAL_LIBRARY"     # Shared domain contracts, shared utilities, SDK package
    DATA_LAYER = "DATA_LAYER"                 # Database models, ORM mappings, persistence repository
    BATCH_WORKER = "BATCH_WORKER"             # Background task worker, message queue consumer
    UNKNOWN = "UNKNOWN"                       # Unclassified repository


class RepositoryMember(BaseModel):
    """Specification of an individual repository member within a multi-repository workspace."""
    model_config = ConfigDict(frozen=True)

    id: str = Field(..., min_length=1, description="Unique identifier of repository in workspace")
    path: str = Field(..., description="Filesystem path relative to workspace manifest root or absolute")
    role: WorkspaceRole = Field(default=WorkspaceRole.INTERNAL_SERVICE)
    criticality: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    tags: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list, description="List of repository IDs this repo depends on")
    git_url: Optional[str] = None
    branch: Optional[str] = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Repository ID cannot be empty or whitespace")
        return clean


class WorkspaceConfig(BaseModel):
    """Workspace-level analysis configuration and policy overrides."""
    model_config = ConfigDict(frozen=True)

    shared_rule_packs: list[str] = Field(default_factory=list, description="Rule packs applied across all member repos")
    cross_repo_taint_depth: int = Field(default=3, ge=1, le=10, description="Max hops for cross-repository taint propagation")
    fail_on_gate: Optional[str] = Field(default=None, description="Workspace CI gate threshold: CRITICAL, HIGH, MEDIUM, LOW")
    organization_id: Optional[str] = None
    distributed_cache_enabled: bool = Field(default=True)
    shared_suppressions_enabled: bool = Field(default=True)


class WorkspaceManifest(BaseModel):
    """Root configuration manifest declaring a multi-repository workspace."""
    model_config = ConfigDict(frozen=True)

    version: str = Field(default="1.0")
    workspace_id: str = Field(..., min_length=1, description="Unique workspace identifier")
    name: str = Field(..., min_length=1, description="Human-readable workspace display name")
    organization_id: Optional[str] = None
    repositories: list[RepositoryMember] = Field(default_factory=list)
    workspace_config: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    manifest_dir: Optional[str] = Field(default=None, description="Base directory containing the manifest file")

    @classmethod
    def from_yaml_str(cls, content: str, manifest_dir: Optional[str | Path] = None) -> WorkspaceManifest:
        """Parse workspace manifest from a YAML string."""
        raw = yaml.safe_load(content)
        if not isinstance(raw, dict):
            raise ValueError("Workspace manifest YAML must parse into a mapping")
        if manifest_dir is not None:
            raw["manifest_dir"] = str(Path(manifest_dir).resolve())
        return cls.model_validate(raw)

    @classmethod
    def from_yaml_file(cls, file_path: str | Path) -> WorkspaceManifest:
        """Load and validate a workspace manifest from a YAML file."""
        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Workspace manifest file not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()
        return cls.from_yaml_str(content, manifest_dir=p.parent)

    def get_repository(self, repo_id: str) -> Optional[RepositoryMember]:
        """Find a repository member by its unique identifier."""
        for r in self.repositories:
            if r.id == repo_id:
                return r
        return None

    def resolve_repository_path(self, repo_member: RepositoryMember) -> Path:
        """Resolve repository path relative to the manifest directory."""
        raw_path = Path(repo_member.path)
        if raw_path.is_absolute():
            return raw_path.resolve()
        base_dir = Path(self.manifest_dir) if self.manifest_dir else Path.cwd()
        return (base_dir / raw_path).resolve()
