"""Component and package-level architecture graph builder.

Aggregates file-level dependency nodes and edges into directory-based components,
collapsing deeper directories according to a configurable maximum depth, and
calculates Robert C. Martin's Package Coupling and Instability Metrics (Ca, Ce, I).
"""

from pathlib import Path
from typing import Optional
import uuid
import networkx as nx

from analyzer.models.graph import (
    ComponentEdge,
    ComponentGraph,
    ComponentNode,
    DependencyEdge,
    DependencyNode,
    PackageMetrics,
)
from analyzer.models.metadata import DiscoveredFileMetadata


def normalize_component_name(relative_file_path: str, max_depth: int = 2) -> tuple[str, str]:
    """Derive normalized component ID and relative directory path for a file.
    
    Args:
        relative_file_path: Normalized repo-relative file path (forward-slash separated).
        max_depth: Maximum directory depth for component grouping.
        
    Returns:
        Tuple of (component_id, component_dir_path).
    """
    clean_path = relative_file_path.replace("\\", "/").strip("/")
    parts = Path(clean_path).parts

    if len(parts) <= 1:
        # File is directly in the repository root directory
        return "root", "root"

    dir_parts = parts[:-1]
    # Collapse directories deeper than max_depth
    collapsed_parts = dir_parts[:max_depth]
    
    comp_id = ".".join(p.lower().replace("-", "_") for p in collapsed_parts)
    comp_path = "/".join(collapsed_parts)
    return comp_id, comp_path


class _BuildDispatcher:
    """Dispatches .build() to either instance execution or class-level graph building."""
    def __get__(self, instance, owner):
        if instance is None:
            def _class_build(graph: ArchitectureGraph, max_depth: int = 2) -> ComponentGraph:
                return owner(graph=graph, max_depth=max_depth).build()
            return _class_build
        else:
            return instance._build_internal


class ComponentGraphBuilder:
    """Aggregates file-level graph topology into a subsystem/package-level ComponentGraph."""

    build = _BuildDispatcher()

    def __init__(
        self,
        files: Optional[list[DiscoveredFileMetadata]] = None,
        file_nodes: Optional[list[DependencyNode]] = None,
        file_edges: Optional[list[DependencyEdge]] = None,
        max_depth: int = 2,
        graph: Optional[ArchitectureGraph] = None,
    ):
        if graph is not None:
            self.file_nodes = list(graph.nodes)
            self.file_edges = list(graph.edges)
            self.files = files or [
                DiscoveredFileMetadata(
                    path=node.file_path,
                    relative_path=node.file_path,
                    extension=Path(node.file_path).suffix,
                    language=node.language.upper() if node.language else "UNKNOWN",
                    size_bytes=0,
                    line_count=node.loc,
                )
                for node in graph.nodes
            ]
        else:
            self.files = files or []
            self.file_nodes = file_nodes or []
            self.file_edges = file_edges or []
        self.max_depth = max(1, max_depth)

    def _build_internal(self) -> ComponentGraph:
        """Construct the ComponentGraph and compute package coupling metrics.
        
        Guarantees:
        - Only repository-local files and LOCAL dependency edges form components.
        - Ca and Ce count distinct other repository components, not import statements.
        - Deeper directories are collapsed deterministically to max_depth.
        - Nodes and edges are sorted deterministically before return.
        """
        # 1. Map files to components
        file_to_comp: dict[str, str] = {}
        comp_dirs: dict[str, str] = {}
        comp_files: dict[str, list[str]] = {}
        comp_loc: dict[str, int] = {}

        # Use discovered files as authoritative source of local repository files
        for f in self.files:
            rel = f.relative_path.replace("\\", "/")
            comp_id, comp_path = normalize_component_name(rel, max_depth=self.max_depth)
            file_to_comp[rel] = comp_id
            comp_dirs[comp_id] = comp_path
            comp_files.setdefault(comp_id, []).append(rel)
            comp_loc[comp_id] = comp_loc.get(comp_id, 0) + f.line_count

        if not comp_files:
            return ComponentGraph(nodes=[], edges=[], circular_components_count=0)

        # 2. Aggregate LOCAL file edges into component edges
        # Inter-component edges map: (source_comp, target_comp) -> list of file edge IDs
        raw_comp_edges: dict[tuple[str, str], list[str]] = {}

        for fe in self.file_edges:
            # Only local edges create inter-component dependencies
            if fe.dependency_category != "LOCAL" or fe.is_external:
                continue

            src_file = fe.source.replace("\\", "/")
            tgt_file = fe.target.replace("\\", "/")

            src_comp = file_to_comp.get(src_file)
            tgt_comp = file_to_comp.get(tgt_file)

            if src_comp and tgt_comp and src_comp != tgt_comp:
                raw_comp_edges.setdefault((src_comp, tgt_comp), []).append(fe.id)

        # 3. Build directed NetworkX graph of components
        G_c = nx.DiGraph()
        for comp_id in comp_files:
            G_c.add_node(comp_id)

        for (src_comp, tgt_comp), edge_ids in raw_comp_edges.items():
            G_c.add_edge(src_comp, tgt_comp, weight=len(edge_ids), file_edges=edge_ids)

        # 4. Cycle detection via Strongly Connected Components (SCC)
        circular_components_count = 0
        scc_component_set: set[str] = set()
        scc_participating_edges: set[tuple[str, str]] = set()

        try:
            sccs = list(nx.strongly_connected_components(G_c))
            for scc in sccs:
                if len(scc) >= 2:
                    circular_components_count += len(scc)
                    scc_component_set.update(scc)
                    # Mark participating directed edges inside this SCC
                    for u in scc:
                        for v in scc:
                            if G_c.has_edge(u, v):
                                scc_participating_edges.add((u, v))
        except Exception:
            pass

        # 5. Build ComponentEdge list
        edges: list[ComponentEdge] = []
        for (src_comp, tgt_comp), edge_ids in raw_comp_edges.items():
            edge_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{src_comp}->{tgt_comp}"))
            is_circ = (src_comp, tgt_comp) in scc_participating_edges
            edges.append(
                ComponentEdge(
                    id=edge_id,
                    source=src_comp,
                    target=tgt_comp,
                    weight=len(edge_ids),
                    is_circular=is_circ,
                    file_edges=sorted(edge_ids),
                )
            )

        # 6. Compute Robert C. Martin's Package Coupling & Instability Metrics
        # Ca: Distinct other repository components importing this component (in-degree in G_c)
        # Ce: Distinct other repository components this component imports (out-degree in G_c)
        # I = Ce / (Ca + Ce)
        nodes: list[ComponentNode] = []
        for comp_id, files_list in comp_files.items():
            ca = G_c.in_degree(comp_id) if comp_id in G_c else 0
            ce = G_c.out_degree(comp_id) if comp_id in G_c else 0
            instability = round(ce / (ca + ce), 4) if (ca + ce) > 0 else 0.0

            metrics = PackageMetrics(
                afferent_coupling=ca,
                efferent_coupling=ce,
                instability=instability,
                total_loc=comp_loc.get(comp_id, 0),
                file_count=len(files_list),
            )

            nodes.append(
                ComponentNode(
                    id=comp_id,
                    path=comp_dirs[comp_id],
                    layer=None,  # Layer populated by LayerBoundaryAnalyzer
                    metrics=metrics,
                    files=sorted(files_list),
                )
            )

        # 7. Strictly sort nodes and edges deterministically
        nodes.sort(key=lambda n: n.id)
        edges.sort(key=lambda e: (e.source, e.target))

        return ComponentGraph(
            nodes=nodes,
            edges=edges,
            circular_components_count=circular_components_count,
        )
