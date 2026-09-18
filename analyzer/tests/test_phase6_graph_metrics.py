"""Phase 6: Graph metrics and structure tests.

Tests cover:
- graph.nodes contains zero external fabricated nodes
- Enriched dependency category counts (local, stdlib, external, unresolved)
- Weakly and strongly connected component counts
- Deterministic ordering of nodes, edges, diagnostics, and cycles
"""

import pytest
import networkx as nx
from analyzer.architecture.graph_builder import ArchitectureGraphBuilder
from analyzer.architecture.metrics import ArchitectureMetricsCalculator
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile
from analyzer.models.graph import ImportType
from pathlib import Path


def _make_file(rel_path: str, lang: str = "PYTHON") -> DiscoveredFileMetadata:
    return DiscoveredFileMetadata(
        path=f"/repo/{rel_path}",
        relative_path=rel_path,
        extension=Path(rel_path).suffix,
        language=lang,
        size_bytes=100,
        line_count=10,
    )


def _make_parsed_file(rel_path: str, language: str, imports: list) -> ParsedFile:
    return ParsedFile(
        file_path=f"/repo/{rel_path}",
        relative_path=rel_path,
        language=language,
        success=True,
        imports=imports,
        exports=[],
        symbols=[],
        errors=[],
        loc=10,
    )


class TestNoExternalNodes:
    """Verify graph.nodes contains zero fabricated external nodes."""

    def test_graph_contains_only_local_nodes(self):
        """Graph nodes should contain ONLY discovered repository files."""
        files = [
            _make_file("app/main.py"),
            _make_file("app/utils.py"),
        ]
        imports = [
            ImportStatement(
                source_module="flask",
                imported_names=["Flask"],
                import_type=ImportType.STATIC,
                line_number=1,
                is_relative=False,
                dependency_category=ImportCategory.EXTERNAL,
            ),
            ImportStatement(
                source_module="./utils",
                imported_names=[],
                import_type=ImportType.STATIC,
                line_number=2,
                is_relative=True,
                dependency_category=ImportCategory.LOCAL,
                resolved_path="app/utils.py",
            ),
        ]
        parsed_files = [
            _make_parsed_file("app/main.py", "PYTHON", imports),
            _make_parsed_file("app/utils.py", "PYTHON", []),
        ]

        builder = ArchitectureGraphBuilder(files, parsed_files)
        G, nodes, edges = builder.build()

        # No external nodes
        assert all(not n.is_external for n in nodes)
        assert len(nodes) == 2
        # G should only contain local nodes
        for node_id in G.nodes:
            assert G.nodes[node_id].get("is_external", False) is False

    def test_external_edges_still_recorded(self):
        """External dependencies are recorded on edges, not as nodes."""
        files = [_make_file("app/main.py")]
        imports = [
            ImportStatement(
                source_module="flask",
                imported_names=["Flask"],
                import_type=ImportType.STATIC,
                line_number=1,
                is_relative=False,
                dependency_category=ImportCategory.EXTERNAL,
            ),
        ]
        parsed_files = [_make_parsed_file("app/main.py", "PYTHON", imports)]

        builder = ArchitectureGraphBuilder(files, parsed_files)
        G, nodes, edges = builder.build()

        assert len(nodes) == 1
        assert len(edges) == 1
        assert edges[0].dependency_category == "EXTERNAL"
        assert edges[0].is_external is True


class TestEnrichedMetrics:
    """Verify enriched dependency category counts and connected components."""

    def _build_graph_with_mixed_deps(self):
        """Build a test graph with LOCAL, STDLIB, EXTERNAL, and UNRESOLVED deps."""
        files = [
            _make_file("app/main.py"),
            _make_file("app/utils.py"),
            _make_file("app/models.py"),
        ]
        imports_main = [
            ImportStatement(
                source_module="app.utils",
                imported_names=[],
                import_type=ImportType.STATIC,
                line_number=1,
                is_relative=False,
                dependency_category=ImportCategory.LOCAL,
                resolved_path="app/utils.py",
            ),
            ImportStatement(
                source_module="os",
                imported_names=[],
                import_type=ImportType.STATIC,
                line_number=2,
                is_relative=False,
                dependency_category=ImportCategory.STDLIB,
            ),
            ImportStatement(
                source_module="flask",
                imported_names=["Flask"],
                import_type=ImportType.STATIC,
                line_number=3,
                is_relative=False,
                dependency_category=ImportCategory.EXTERNAL,
            ),
            ImportStatement(
                source_module=".missing",
                imported_names=[],
                import_type=ImportType.STATIC,
                line_number=4,
                is_relative=True,
                dependency_category=ImportCategory.UNRESOLVED,
            ),
        ]
        imports_utils = [
            ImportStatement(
                source_module="app.models",
                imported_names=[],
                import_type=ImportType.STATIC,
                line_number=1,
                is_relative=False,
                dependency_category=ImportCategory.LOCAL,
                resolved_path="app/models.py",
            ),
        ]
        parsed_files = [
            _make_parsed_file("app/main.py", "PYTHON", imports_main),
            _make_parsed_file("app/utils.py", "PYTHON", imports_utils),
            _make_parsed_file("app/models.py", "PYTHON", []),
        ]

        builder = ArchitectureGraphBuilder(files, parsed_files)
        G, nodes, edges = builder.build()
        return G, nodes, edges

    def test_dependency_category_counts(self):
        """Verify per-category dependency counts are accurate."""
        G, nodes, edges = self._build_graph_with_mixed_deps()
        graph = ArchitectureMetricsCalculator.compute(G, nodes, edges)

        assert graph.metrics.local_dependencies_count == 2
        assert graph.metrics.stdlib_dependencies_count == 1
        assert graph.metrics.external_dependencies_count == 1
        assert graph.metrics.unresolved_dependencies_count == 1

    def test_connected_components(self):
        """Verify connected component counts."""
        G, nodes, edges = self._build_graph_with_mixed_deps()
        graph = ArchitectureMetricsCalculator.compute(G, nodes, edges)

        # All 3 local nodes are connected: main -> utils -> models
        assert graph.metrics.connected_components_count == 1
        # No cycles, so each node is its own SCC
        assert graph.metrics.strongly_connected_components_count == 3


class TestDeterministicOrdering:
    """Verify deterministic ordering of graph elements."""

    def test_nodes_sorted_by_id(self):
        """Nodes must be sorted by ID."""
        files = [
            _make_file("z_module.py"),
            _make_file("a_module.py"),
            _make_file("m_module.py"),
        ]
        parsed_files = [
            _make_parsed_file("z_module.py", "PYTHON", []),
            _make_parsed_file("a_module.py", "PYTHON", []),
            _make_parsed_file("m_module.py", "PYTHON", []),
        ]
        builder = ArchitectureGraphBuilder(files, parsed_files)
        G, nodes, edges = builder.build()
        graph = ArchitectureMetricsCalculator.compute(G, nodes, edges)

        node_ids = [n.id for n in graph.nodes]
        assert node_ids == sorted(node_ids)

    def test_edges_sorted_deterministically(self):
        """Edges must be sorted by (source, target, import_type, category, line_number)."""
        files = [_make_file("a.py"), _make_file("b.py"), _make_file("c.py")]
        imports_a = [
            ImportStatement(
                source_module="c", imported_names=[], import_type=ImportType.STATIC,
                line_number=1, is_relative=False, dependency_category=ImportCategory.LOCAL,
                resolved_path="c.py",
            ),
            ImportStatement(
                source_module="b", imported_names=[], import_type=ImportType.STATIC,
                line_number=2, is_relative=False, dependency_category=ImportCategory.LOCAL,
                resolved_path="b.py",
            ),
        ]
        parsed_files = [
            _make_parsed_file("a.py", "PYTHON", imports_a),
            _make_parsed_file("b.py", "PYTHON", []),
            _make_parsed_file("c.py", "PYTHON", []),
        ]
        builder = ArchitectureGraphBuilder(files, parsed_files)
        G, nodes, edges = builder.build()
        graph = ArchitectureMetricsCalculator.compute(G, nodes, edges)

        # Edges should be sorted: a.py->b.py before a.py->c.py
        assert graph.edges[0].target == "b.py"
        assert graph.edges[1].target == "c.py"
