"""Multi-repository workspace orchestration package (Phase 28)."""

from analyzer.workspace.models import (
    RepositoryMember,
    WorkspaceConfig,
    WorkspaceManifest,
    WorkspaceRole,
)
from analyzer.workspace.dag import (
    CircularWorkspaceDependencyError,
    UnknownRepositoryDependencyError,
    WorkspaceDAG,
)
from analyzer.workspace.federated_contracts import (
    CrossRepoCallLink,
    FederatedContractRegistry,
)

__all__ = [
    "WorkspaceRole",
    "RepositoryMember",
    "WorkspaceConfig",
    "WorkspaceManifest",
    "CircularWorkspaceDependencyError",
    "UnknownRepositoryDependencyError",
    "WorkspaceDAG",
    "CrossRepoCallLink",
    "FederatedContractRegistry",
]
