"""Unit tests for Phase 7 ComponentGraphBuilder and Robert C. Martin coupling metrics."""

import pytest
from pathlib import Path
from analyzer.architecture.components import ComponentGraphBuilder
from analyzer.models.graph import ArchitectureGraph, DependencyEdge, DependencyNode


def test_component_graph_empty():
    graph = ArchitectureGraph()
    cg = ComponentGraphBuilder.build(graph, max_depth=2)
    assert len(cg.nodes) == 0
    assert len(cg.edges) == 0
    assert cg.total_components == 0


def test_component_graph_root_files():
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="main.py", file_path="main.py", module_name="main", language="python", loc=10),
            DependencyNode(id="config.py", file_path="config.py", module_name="config", language="python", loc=20),
        ],
        edges=[
            DependencyEdge(id="e1", source="main.py", target="config.py", import_type="STATIC", dependency_category="LOCAL"),
        ]
    )
    cg = ComponentGraphBuilder.build(graph, max_depth=2)
    assert len(cg.nodes) == 1
    assert cg.nodes[0].id == "root"
    assert set(cg.nodes[0].files) == {"main.py", "config.py"}
    # Intra-component edge should not create an inter-component edge
    assert len(cg.edges) == 0
    assert cg.nodes[0].metrics.afferent_coupling == 0
    assert cg.nodes[0].metrics.efferent_coupling == 0
    assert cg.nodes[0].metrics.instability == 0.0


def test_component_graph_distinct_coupling_metrics():
    """Verify Ca and Ce count DISTINCT other components, not raw file edges."""
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="comp_a/f1.py", file_path="comp_a/f1.py", module_name="comp_a.f1", language="python"),
            DependencyNode(id="comp_a/f2.py", file_path="comp_a/f2.py", module_name="comp_a.f2", language="python"),
            DependencyNode(id="comp_b/f1.py", file_path="comp_b/f1.py", module_name="comp_b.f1", language="python"),
            DependencyNode(id="comp_b/f2.py", file_path="comp_b/f2.py", module_name="comp_b.f2", language="python"),
            DependencyNode(id="comp_c/f1.py", file_path="comp_c/f1.py", module_name="comp_c.f1", language="python"),
        ],
        edges=[
            # comp_a has 3 file edges to comp_b
            DependencyEdge(id="e1", source="comp_a/f1.py", target="comp_b/f1.py", import_type="STATIC", dependency_category="LOCAL"),
            DependencyEdge(id="e2", source="comp_a/f1.py", target="comp_b/f2.py", import_type="STATIC", dependency_category="LOCAL"),
            DependencyEdge(id="e3", source="comp_a/f2.py", target="comp_b/f1.py", import_type="STATIC", dependency_category="LOCAL"),
            # comp_a has 1 file edge to comp_c
            DependencyEdge(id="e4", source="comp_a/f2.py", target="comp_c/f1.py", import_type="STATIC", dependency_category="LOCAL"),
        ]
    )
    cg = ComponentGraphBuilder.build(graph, max_depth=1)
    comp_map = {n.id: n for n in cg.nodes}
    
    assert "comp_a" in comp_map
    assert "comp_b" in comp_map
    assert "comp_c" in comp_map

    node_a = comp_map["comp_a"]
    # Efferent coupling should be 2 (comp_b and comp_c), NOT 4 (file edges)
    assert node_a.metrics.efferent_coupling == 2
    assert node_a.metrics.afferent_coupling == 0
    # Instability = 2 / (0 + 2) = 1.0
    assert node_a.metrics.instability == 1.0

    node_b = comp_map["comp_b"]
    # Afferent coupling should be 1 (only comp_a calls it)
    assert node_b.metrics.afferent_coupling == 1
    assert node_b.metrics.efferent_coupling == 0
    # Instability = 0 / (1 + 0) = 0.0
    assert node_b.metrics.instability == 0.0

    # Verify component edges
    edge_ab = next((e for e in cg.edges if e.source == "comp_a" and e.target == "comp_b"), None)
    assert edge_ab is not None
    assert edge_ab.weight == 3
    assert len(edge_ab.file_edges) == 3


def test_component_depth_collapsing():
    """Verify max_depth correctly collapses deeply nested subpackages."""
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="a/b/c/d/deep.py", file_path="a/b/c/d/deep.py", module_name="a.b.c.d.deep", language="python"),
            DependencyNode(id="a/b/c/other.py", file_path="a/b/c/other.py", module_name="a.b.c.other", language="python"),
            DependencyNode(id="a/b/sibling.py", file_path="a/b/sibling.py", module_name="a.b.sibling", language="python"),
        ],
        edges=[]
    )
    # With max_depth=2, all should map to a.b
    cg = ComponentGraphBuilder.build(graph, max_depth=2)
    assert len(cg.nodes) == 1
    assert cg.nodes[0].id == "a.b"
    assert len(cg.nodes[0].files) == 3

    # With max_depth=1, all should map to a
    cg1 = ComponentGraphBuilder.build(graph, max_depth=1)
    assert len(cg1.nodes) == 1
    assert cg1.nodes[0].id == "a"
    assert len(cg1.nodes[0].files) == 3


def test_component_package_boundary_preservation():
    """Verify directory with __init__.py or index.ts is recognized as a package."""
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="pkg/__init__.py", file_path="pkg/__init__.py", module_name="pkg", language="python"),
            DependencyNode(id="pkg/sub/mod.py", file_path="pkg/sub/mod.py", module_name="pkg.sub.mod", language="python"),
        ],
        edges=[]
    )
    cg = ComponentGraphBuilder.build(graph, max_depth=2)
    # pkg is a recognized package
    node_ids = {n.id for n in cg.nodes}
    assert "pkg" in node_ids or "pkg.sub" in node_ids
