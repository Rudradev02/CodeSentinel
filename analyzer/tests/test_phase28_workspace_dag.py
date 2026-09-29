"""Unit tests for Phase 28 Multi-Repository Workspace Manifest and DAG Resolver."""

import pytest

from analyzer.models.findings import FindingSeverity
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

SAMPLE_WORKSPACE_YAML = """
version: "1.0"
workspace_id: "fintech-fleet"
name: "Fintech Fleet Core"
organization_id: "org-acme"
repositories:
  - id: "auth-contracts"
    path: "libs/auth"
    role: "INTERNAL_LIBRARY"
    criticality: "HIGH"
    tags: ["auth", "contracts"]
    depends_on: []

  - id: "db-layer"
    path: "services/db"
    role: "DATA_LAYER"
    criticality: "CRITICAL"
    tags: ["database", "pci"]
    depends_on: []

  - id: "payment-core"
    path: "services/payment"
    role: "INTERNAL_SERVICE"
    criticality: "CRITICAL"
    tags: ["pci", "backend"]
    depends_on:
      - "auth-contracts"
      - "db-layer"

  - id: "api-gateway"
    path: "services/gateway"
    role: "PUBLIC_ENTRYPOINT"
    criticality: "HIGH"
    tags: ["ingress", "web"]
    depends_on:
      - "payment-core"
      - "auth-contracts"

workspace_config:
  shared_rule_packs:
    - "pci-dss-v4"
  cross_repo_taint_depth: 4
  fail_on_gate: "HIGH"
"""


class TestWorkspaceManifest:
    """Tests for workspace manifest parsing and validation."""

    def test_parse_valid_manifest(self):
        manifest = WorkspaceManifest.from_yaml_str(SAMPLE_WORKSPACE_YAML)
        assert manifest.workspace_id == "fintech-fleet"
        assert manifest.name == "Fintech Fleet Core"
        assert manifest.organization_id == "org-acme"
        assert len(manifest.repositories) == 4

        gateway = manifest.get_repository("api-gateway")
        assert gateway is not None
        assert gateway.role == WorkspaceRole.PUBLIC_ENTRYPOINT
        assert gateway.criticality == FindingSeverity.HIGH
        assert gateway.depends_on == ["payment-core", "auth-contracts"]

    def test_manifest_config(self):
        manifest = WorkspaceManifest.from_yaml_str(SAMPLE_WORKSPACE_YAML)
        assert manifest.workspace_config.shared_rule_packs == ["pci-dss-v4"]
        assert manifest.workspace_config.cross_repo_taint_depth == 4
        assert manifest.workspace_config.fail_on_gate == "HIGH"


class TestWorkspaceDAG:
    """Tests for workspace topological dependency graph and wave scheduler."""

    def test_dag_topological_sort(self):
        manifest = WorkspaceManifest.from_yaml_str(SAMPLE_WORKSPACE_YAML)
        dag = WorkspaceDAG(manifest)

        order = dag.get_topological_order()
        # auth-contracts and db-layer must precede payment-core
        assert order.index("auth-contracts") < order.index("payment-core")
        assert order.index("db-layer") < order.index("payment-core")
        # payment-core must precede api-gateway
        assert order.index("payment-core") < order.index("api-gateway")

    def test_execution_waves(self):
        manifest = WorkspaceManifest.from_yaml_str(SAMPLE_WORKSPACE_YAML)
        dag = WorkspaceDAG(manifest)

        waves = dag.get_execution_waves()
        assert len(waves) == 3
        # Wave 0: Base dependencies with zero in-degree
        assert waves[0] == ["auth-contracts", "db-layer"]
        # Wave 1: payment-core depends on Wave 0
        assert waves[1] == ["payment-core"]
        # Wave 2: api-gateway depends on payment-core & auth-contracts
        assert waves[2] == ["api-gateway"]

    def test_direct_and_transitive_dependencies(self):
        manifest = WorkspaceManifest.from_yaml_str(SAMPLE_WORKSPACE_YAML)
        dag = WorkspaceDAG(manifest)

        assert dag.get_direct_dependencies("payment-core") == ["auth-contracts", "db-layer"]
        assert dag.get_direct_dependents("payment-core") == ["api-gateway"]

        transitive = dag.get_transitive_dependencies("api-gateway")
        assert transitive == {"payment-core", "auth-contracts", "db-layer"}

        downstream = dag.get_transitive_dependents("db-layer")
        assert downstream == {"payment-core", "api-gateway"}

    def test_circular_dependency_rejection(self):
        cyclic_yaml = """
version: "1.0"
workspace_id: "cyclic-fleet"
name: "Cyclic Fleet"
repositories:
  - id: "repo-a"
    path: "services/a"
    depends_on: ["repo-b"]
  - id: "repo-b"
    path: "services/b"
    depends_on: ["repo-c"]
  - id: "repo-c"
    path: "services/c"
    depends_on: ["repo-a"]
"""
        manifest = WorkspaceManifest.from_yaml_str(cyclic_yaml)
        with pytest.raises(CircularWorkspaceDependencyError) as exc_info:
            WorkspaceDAG(manifest)
        assert "Circular cross-repository dependency detected" in str(exc_info.value)

    def test_unknown_dependency_rejection(self):
        unknown_dep_yaml = """
version: "1.0"
workspace_id: "broken-fleet"
name: "Broken Fleet"
repositories:
  - id: "repo-a"
    path: "services/a"
    depends_on: ["non-existent-repo"]
"""
        manifest = WorkspaceManifest.from_yaml_str(unknown_dep_yaml)
        with pytest.raises(UnknownRepositoryDependencyError) as exc_info:
            WorkspaceDAG(manifest)
        assert "non-existent-repo" in str(exc_info.value)

    def test_independent_repositories_parallel_wave(self):
        independent_yaml = """
version: "1.0"
workspace_id: "disjoint-fleet"
name: "Disjoint Fleet"
repositories:
  - id: "service-1"
    path: "services/1"
    depends_on: []
  - id: "service-2"
    path: "services/2"
    depends_on: []
  - id: "service-3"
    path: "services/3"
    depends_on: []
"""
        manifest = WorkspaceManifest.from_yaml_str(independent_yaml)
        dag = WorkspaceDAG(manifest)
        waves = dag.get_execution_waves()
        assert len(waves) == 1
        assert sorted(waves[0]) == ["service-1", "service-2", "service-3"]
