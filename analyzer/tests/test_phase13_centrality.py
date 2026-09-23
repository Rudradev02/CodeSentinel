"""Tests for repository-local component graph centrality metrics calculator."""

import pytest
from analyzer.architecture.centrality import CentralityCalculator
from analyzer.models.graph import ComponentEdge, ComponentGraph, ComponentNode, PackageMetrics


def _make_component_node(comp_id: str, files: list[str]) -> ComponentNode:
    return ComponentNode(
        id=comp_id,
        path=comp_id.replace(".", "/"),
        metrics=PackageMetrics(
            afferent_coupling=0,
            efferent_coupling=0,
            instability=0.0,
            total_loc=100,
            file_count=len(files),
        ),
        files=files,
    )


def test_centrality_calculator_line_graph():
    """Verify betweenness centrality on a linear mediation topology (A -> B -> C)."""
    # A -> B -> C: B mediates all shortest paths between A and C
    nodes = [
        _make_component_node("comp_a", ["comp_a/file1.py", "comp_a/file2.py"]),
        _make_component_node("comp_b", ["comp_b/file1.py", "comp_b/file2.py"]),
        _make_component_node("comp_c", ["comp_c/file1.py", "comp_c/file2.py"]),
    ]
    edges = [
        ComponentEdge(id="e1", source="comp_a", target="comp_b", weight=1),
        ComponentEdge(id="e2", source="comp_b", target="comp_c", weight=1),
    ]
    graph = ComponentGraph(nodes=nodes, edges=edges)

    computed = CentralityCalculator.compute(graph)
    node_map = {n.id: n for n in computed.nodes}

    # B has positive betweenness, while A and C have 0
    assert node_map["comp_b"].metrics.betweenness_centrality > 0.0
    assert node_map["comp_a"].metrics.betweenness_centrality == 0.0
    assert node_map["comp_c"].metrics.betweenness_centrality == 0.0

    # In/Out degree checks
    assert node_map["comp_a"].metrics.out_degree_centrality == 0.5
    assert node_map["comp_b"].metrics.in_degree_centrality == 0.5
    assert node_map["comp_b"].metrics.out_degree_centrality == 0.5
    assert node_map["comp_c"].metrics.in_degree_centrality == 0.5


def test_centrality_calculator_isolated_nodes():
    """Verify that isolated nodes receive 0.0 for all centrality metrics."""
    nodes = [
        _make_component_node("isolated_1", ["f1.py"]),
        _make_component_node("isolated_2", ["f2.py"]),
    ]
    graph = ComponentGraph(nodes=nodes, edges=[])
    computed = CentralityCalculator.compute(graph)
    for n in computed.nodes:
        assert n.metrics.betweenness_centrality == 0.0
        assert n.metrics.in_degree_centrality == 0.0
        assert n.metrics.out_degree_centrality == 0.0


def test_centrality_calculator_empty_or_single():
    """Verify handling of empty or 1-node graphs without crashing."""
    empty_graph = ComponentGraph(nodes=[], edges=[])
    computed_empty = CentralityCalculator.compute(empty_graph)
    assert len(computed_empty.nodes) == 0

    single_node = [_make_component_node("single", ["file.py"])]
    single_graph = ComponentGraph(nodes=single_node, edges=[])
    computed_single = CentralityCalculator.compute(single_graph)
    assert computed_single.nodes[0].metrics.betweenness_centrality == 0.0
