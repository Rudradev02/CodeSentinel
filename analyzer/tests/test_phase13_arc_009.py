"""Tests for ARC-009: High-Centrality Architectural Bottleneck rule."""

import pytest
from analyzer.architecture.centrality import CentralityCalculator
from analyzer.architecture.rules.arc_009_centrality import RuleArc009
from analyzer.models.graph import (
    ArchitectureGraph,
    ComponentEdge,
    ComponentGraph,
    ComponentNode,
    PackageMetrics,
)


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


def test_arc_009_triggers_on_high_betweenness_component():
    """Verify that ARC-009 flags a high-betweenness component in a 5+ component repository."""
    # Star / bow-tie topology:
    # A -> HUB -> D
    # B -> HUB -> E
    # HUB mediates all communication between (A, B) and (D, E)
    nodes = [
        _make_component_node("comp_a", ["a/1.py", "a/2.py"]),
        _make_component_node("comp_b", ["b/1.py", "b/2.py"]),
        _make_component_node("comp_hub", ["hub/1.py", "hub/2.py"]),
        _make_component_node("comp_d", ["d/1.py", "d/2.py"]),
        _make_component_node("comp_e", ["e/1.py", "e/2.py"]),
    ]
    edges = [
        ComponentEdge(id="e1", source="comp_a", target="comp_hub", weight=1),
        ComponentEdge(id="e2", source="comp_hub", target="comp_a", weight=1),
        ComponentEdge(id="e3", source="comp_b", target="comp_hub", weight=1),
        ComponentEdge(id="e4", source="comp_hub", target="comp_b", weight=1),
        ComponentEdge(id="e5", source="comp_hub", target="comp_d", weight=1),
        ComponentEdge(id="e6", source="comp_d", target="comp_hub", weight=1),
        ComponentEdge(id="e7", source="comp_hub", target="comp_e", weight=1),
        ComponentEdge(id="e8", source="comp_e", target="comp_hub", weight=1),
    ]
    comp_graph = ComponentGraph(nodes=nodes, edges=edges)
    comp_graph = CentralityCalculator.compute(comp_graph)

    arch_graph = ArchitectureGraph(component_graph=comp_graph)

    rule = RuleArc009(threshold=0.35)
    findings = rule.analyze(arch_graph)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ARC-009"
    assert f.evidence["component_id"] == "comp_hub"
    assert f.evidence["betweenness_centrality"] >= 0.35
    assert "mediation hotspot" in f.message
    # Invariant: Never claim literal "single point of failure"
    assert "single point of failure" not in f.message.lower()


def test_arc_009_suppressed_on_small_codebases():
    """Verify ARC-009 does NOT trigger when total components < 5."""
    nodes = [
        _make_component_node("comp_a", ["a/1.py", "a/2.py"]),
        _make_component_node("comp_hub", ["hub/1.py", "hub/2.py"]),
        _make_component_node("comp_c", ["c/1.py", "c/2.py"]),
    ]
    edges = [
        ComponentEdge(id="e1", source="comp_a", target="comp_hub", weight=1),
        ComponentEdge(id="e2", source="comp_hub", target="comp_c", weight=1),
    ]
    comp_graph = ComponentGraph(nodes=nodes, edges=edges)
    comp_graph = CentralityCalculator.compute(comp_graph)
    arch_graph = ArchitectureGraph(component_graph=comp_graph)

    rule = RuleArc009(threshold=0.20)
    findings = rule.analyze(arch_graph)
    assert len(findings) == 0


def test_arc_009_excludes_single_file_components():
    """Verify ARC-009 excludes leaf components with file_count < 2."""
    nodes = [
        _make_component_node("comp_a", ["a/1.py", "a/2.py"]),
        _make_component_node("comp_b", ["b/1.py", "b/2.py"]),
        _make_component_node("comp_hub", ["hub/single_file.py"]),  # Only 1 file
        _make_component_node("comp_d", ["d/1.py", "d/2.py"]),
        _make_component_node("comp_e", ["e/1.py", "e/2.py"]),
    ]
    edges = [
        ComponentEdge(id="e1", source="comp_a", target="comp_hub", weight=1),
        ComponentEdge(id="e2", source="comp_b", target="comp_hub", weight=1),
        ComponentEdge(id="e3", source="comp_hub", target="comp_d", weight=1),
        ComponentEdge(id="e4", source="comp_hub", target="comp_e", weight=1),
    ]
    comp_graph = ComponentGraph(nodes=nodes, edges=edges)
    comp_graph = CentralityCalculator.compute(comp_graph)
    arch_graph = ArchitectureGraph(component_graph=comp_graph)

    rule = RuleArc009(threshold=0.35)
    findings = rule.analyze(arch_graph)
    assert len(findings) == 0
