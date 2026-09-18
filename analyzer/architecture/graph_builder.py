"""Directed architecture dependency graph builder using NetworkX.

Phase 6: Strictly repository-local graph. No fabricated external nodes.
NetworkX G and nodes_map contain ONLY discovered repository files as nodes.
All dependencies (LOCAL, STDLIB, EXTERNAL, UNRESOLVED) are preserved on
DependencyEdge objects with their respective dependency_category and is_external flags.
"""

from typing import Optional
import uuid
import networkx as nx

from analyzer.models.graph import (
    ArchitectureGraph,
    DependencyEdge,
    DependencyNode,
    ImportType,
)
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ParsedFile


class ArchitectureGraphBuilder:
    """Constructs a directed graph representing repository module dependencies.
    
    Phase 6 invariant: graph.nodes and NetworkX G contain ONLY discovered
    repository files. No synthetic external nodes are fabricated.
    """

    def __init__(self, files: list[DiscoveredFileMetadata], parsed_files: list[ParsedFile]):
        self.files = files
        self.parsed_files = parsed_files

    def build(self) -> tuple[nx.DiGraph, list[DependencyNode], list[DependencyEdge]]:
        """Build directed graph G and raw node/edge model lists.
        
        Returns:
            Tuple of (NetworkX DiGraph, list of DependencyNode, list of DependencyEdge).
            
        Phase 6 guarantees:
        - G contains ONLY discovered repository files as nodes.
        - No fabricated external nodes with loc=0 are added.
        - LOCAL edges create directed edges in G.
        - Non-local edges (STDLIB, EXTERNAL, UNRESOLVED) are recorded on
          DependencyEdge objects but do NOT create nodes in G.
        """
        G = nx.DiGraph()
        nodes_map: dict[str, DependencyNode] = {}
        edges: list[DependencyEdge] = []

        # 1. Register all discovered local repository files as nodes
        for f in self.files:
            rel = f.relative_path.replace("\\", "/")
            mod_name = rel.replace("/", ".")
            if mod_name.endswith(".py"):
                mod_name = mod_name[:-3]

            node = DependencyNode(
                id=rel,
                file_path=rel,
                module_name=mod_name,
                language=f.language,
                loc=f.line_count,
                fan_in=0,
                fan_out=0,
                dependencies_count=0,
                dependents_count=0,
                is_external=False,
                is_god_module=False,
            )
            nodes_map[rel] = node
            G.add_node(
                rel,
                file_path=rel,
                module_name=mod_name,
                language=f.language,
                loc=f.line_count,
                is_external=False,
            )

        # 2. Add edges from parsed import statements
        for pf in self.parsed_files:
            source_id = pf.relative_path.replace("\\", "/")
            if source_id not in nodes_map:
                continue

            for imp in pf.imports:
                is_local = imp.dependency_category == ImportCategory.LOCAL and imp.resolved_path
                target_id = imp.resolved_path if is_local else imp.source_module

                edge_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_OID,
                        f"{source_id}->{target_id}:{imp.line_number}:{imp.import_type.value}",
                    )
                )
                edge = DependencyEdge(
                    id=edge_id,
                    source=source_id,
                    target=target_id,
                    import_type=imp.import_type,
                    is_circular=False,
                    is_external=not is_local,
                    dependency_category=imp.dependency_category.value,
                    line_number=imp.line_number,
                )
                edges.append(edge)

                # Phase 6: Only add edges to NetworkX graph for LOCAL dependencies
                # Do NOT fabricate external nodes
                if is_local and target_id in nodes_map:
                    G.add_edge(
                        source_id,
                        target_id,
                        import_type=imp.import_type.value,
                        is_local=True,
                        category=imp.dependency_category.value,
                        line_number=imp.line_number,
                    )

        return G, list(nodes_map.values()), edges
