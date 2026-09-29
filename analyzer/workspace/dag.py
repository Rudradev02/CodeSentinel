"""Topological dependency graph, cycle detection, and wave scheduler for workspaces (Phase 28)."""

from __future__ import annotations

from typing import Optional
import networkx as nx

from analyzer.workspace.models import RepositoryMember, WorkspaceManifest


class CircularWorkspaceDependencyError(Exception):
    """Raised when repository dependencies within a workspace form a cyclic loop."""
    pass


class UnknownRepositoryDependencyError(Exception):
    """Raised when a repository specifies a dependency on an unknown repository ID."""
    pass


class WorkspaceDAG:
    """Directed Acyclic Graph of workspace repositories enforcing topological ordering."""

    def __init__(self, manifest: WorkspaceManifest):
        self.manifest = manifest
        # Directed graph: edge (A, B) means A must be analyzed BEFORE B (B depends on A)
        self.graph = nx.DiGraph()
        self._build_and_validate()

    def _build_and_validate(self) -> None:
        """Construct the dependency graph and assert acyclic invariants."""
        # 1. Add all repository nodes
        for r in self.manifest.repositories:
            self.graph.add_node(r.id, data=r)

        # 2. Add dependency edges: if B depends on A, edge is A -> B
        for r in self.manifest.repositories:
            for dep_id in r.depends_on:
                if not self.graph.has_node(dep_id):
                    raise UnknownRepositoryDependencyError(
                        f"Repository '{r.id}' depends on '{dep_id}', which is not declared in workspace '{self.manifest.workspace_id}'"
                    )
                self.graph.add_edge(dep_id, r.id)

        # 3. Detect circular dependency cycles
        if not nx.is_directed_acyclic_graph(self.graph):
            cycles = list(nx.simple_cycles(self.graph))
            formatted_cycles = [" -> ".join(c + [c[0]]) for c in cycles]
            raise CircularWorkspaceDependencyError(
                f"Circular cross-repository dependency detected in workspace '{self.manifest.workspace_id}': "
                f"{'; '.join(formatted_cycles)}"
            )

    @property
    def repository_ids(self) -> list[str]:
        """All repository IDs declared in the workspace."""
        return list(self.graph.nodes())

    def get_repository_member(self, repo_id: str) -> Optional[RepositoryMember]:
        """Retrieve repository member model by ID."""
        node_data = self.graph.nodes.get(repo_id)
        return node_data.get("data") if node_data else None

    def get_direct_dependencies(self, repo_id: str) -> list[str]:
        """Repositories that repo_id directly depends on (must be analyzed before repo_id)."""
        if not self.graph.has_node(repo_id):
            return []
        return sorted(list(self.graph.predecessors(repo_id)))

    def get_direct_dependents(self, repo_id: str) -> list[str]:
        """Repositories that directly depend on repo_id (analyzed after repo_id)."""
        if not self.graph.has_node(repo_id):
            return []
        return sorted(list(self.graph.successors(repo_id)))

    def get_transitive_dependencies(self, repo_id: str) -> set[str]:
        """All upstream repositories that must be analyzed prior to repo_id."""
        if not self.graph.has_node(repo_id):
            return set()
        return nx.ancestors(self.graph, repo_id)

    def get_transitive_dependents(self, repo_id: str) -> set[str]:
        """All downstream repositories affected if repo_id changes."""
        if not self.graph.has_node(repo_id):
            return set()
        return nx.descendants(self.graph, repo_id)

    def get_topological_order(self) -> list[str]:
        """Compute a linear topological sequence of repository IDs."""
        return list(nx.topological_sort(self.graph))

    def get_execution_waves(self) -> list[list[str]]:
        """Partition repositories into execution waves (tiers).
        
        Wave 0: Repositories with no internal dependencies (can run immediately in parallel).
        Wave 1: Repositories depending only on Wave 0 repositories.
        Wave N: Repositories depending only on prior waves.
        """
        waves: list[list[str]] = []
        in_degree = dict(self.graph.in_degree())
        remaining = set(self.graph.nodes())

        while remaining:
            current_wave = sorted([node for node in remaining if in_degree[node] == 0])
            if not current_wave:
                raise CircularWorkspaceDependencyError("Cycle detected during wave partitioning")

            waves.append(current_wave)
            for node in current_wave:
                remaining.remove(node)
                for successor in self.graph.successors(node):
                    in_degree[successor] -= 1

        return waves
