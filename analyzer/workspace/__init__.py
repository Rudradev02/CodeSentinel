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
from analyzer.workspace.compliance_rollup import (
    FleetComplianceEvaluator,
    WorkspaceComplianceSuite,
    WorkspaceControlRollup,
    WorkspaceFrameworkRollup,
    compute_workspace_merkle_root,
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
    "FleetComplianceEvaluator",
    "WorkspaceComplianceSuite",
    "WorkspaceControlRollup",
    "WorkspaceFrameworkRollup",
    "compute_workspace_merkle_root",
]
