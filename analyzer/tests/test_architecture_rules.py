"""Tests for Architecture Rules (ARC-001 through ARC-004)."""

import networkx as nx

from analyzer.architecture.rules.arc_001_circular import RuleArc001
from analyzer.architecture.rules.arc_002_coupling import RuleArc002
from analyzer.architecture.rules.arc_003_god_module import RuleArc003
from analyzer.architecture.rules.arc_004_deep_chain import RuleArc004
from analyzer.models.findings import EvidenceType, FindingConfidence, FindingSeverity
from analyzer.models.graph import (
    ArchitectureGraph,
    CircularDependency,
    CouplingMetrics,
    DependencyEdge,
    DependencyNode,
)


def _make_sample_graph(
    nodes: list[DependencyNode],
    edges: list[DependencyEdge],
    cycles: list[CircularDependency] | None = None,
) -> ArchitectureGraph:
    return ArchitectureGraph(
        nodes=nodes,
        edges=edges,
        circular_dependencies=cycles or [],
        metrics=CouplingMetrics(
            total_modules=len(nodes),
            total_edges=len(edges),
            circular_cycles_count=len(cycles or []),
        ),
    )


# ==============================================================================
# ARC-001: Circular Dependency
# ==============================================================================
def test_arc_001_real_circular_graph():
    rule = RuleArc001()
    node_a = DependencyNode(id="pkg/a.py", file_path="pkg/a.py", module_name="pkg.a", language="PYTHON")
    node_b = DependencyNode(id="pkg/b.py", file_path="pkg/b.py", module_name="pkg.b", language="PYTHON")
    edge_ab = DependencyEdge(source="pkg/a.py", target="pkg/b.py", is_circular=True, line_number=5)
    edge_ba = DependencyEdge(source="pkg/b.py", target="pkg/a.py", is_circular=True, line_number=10)
    cycle = CircularDependency(modules=["pkg/a.py", "pkg/b.py"], length=2)

    graph = _make_sample_graph([node_a, node_b], [edge_ab, edge_ba], [cycle])
    findings = rule.analyze(graph)

    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-001"
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].location.file_path == "pkg/a.py"
    assert findings[0].location.line_start == 5


def test_arc_001_acyclic_graph():
    rule = RuleArc001()
    node_a = DependencyNode(id="pkg/a.py", file_path="pkg/a.py", module_name="pkg.a", language="PYTHON")
    node_b = DependencyNode(id="pkg/b.py", file_path="pkg/b.py", module_name="pkg.b", language="PYTHON")
    edge_ab = DependencyEdge(source="pkg/a.py", target="pkg/b.py")

    graph = _make_sample_graph([node_a, node_b], [edge_ab], cycles=[])
    findings = rule.analyze(graph)
    assert len(findings) == 0


# ==============================================================================
# ARC-002: Excessive Fan-Out / Coupling
# ==============================================================================
def test_arc_002_excessive_fan_out():
    rule = RuleArc002(threshold=10)
    node_hub = DependencyNode(
        id="pkg/hub.py",
        file_path="pkg/hub.py",
        module_name="pkg.hub",
        language="PYTHON",
        fan_out=15,  # Exceeds threshold of 10
    )
    graph = _make_sample_graph([node_hub], [])
    findings = rule.analyze(graph)

    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-002"
    assert findings[0].severity == FindingSeverity.MEDIUM
    assert "15" in findings[0].description


def test_arc_002_normal_fan_out():
    rule = RuleArc002(threshold=10)
    node_normal = DependencyNode(
        id="pkg/normal.py",
        file_path="pkg/normal.py",
        module_name="pkg.normal",
        language="PYTHON",
        fan_out=4,
    )
    graph = _make_sample_graph([node_normal], [])
    findings = rule.analyze(graph)
    assert len(findings) == 0


# ==============================================================================
# ARC-003: God Module
# ==============================================================================
def test_arc_003_god_module_detected():
    rule = RuleArc003()
    # Satisfies condition 1: LOC > 500 and fan_out > 8 and fan_in > 5
    god_node = DependencyNode(
        id="pkg/god.py",
        file_path="pkg/god.py",
        module_name="pkg.god",
        language="PYTHON",
        loc=650,
        fan_out=12,
        fan_in=9,
        is_god_module=False,
    )
    graph = _make_sample_graph([god_node], [])
    findings = rule.analyze(graph)

    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-003"
    assert findings[0].severity == FindingSeverity.HIGH
    assert god_node.is_god_module is True
    assert "650" in findings[0].description


def test_arc_003_normal_large_module_not_god():
    rule = RuleArc003()
    # Large LOC (e.g. 600) but low coupling (fan_out=2, fan_in=1)
    large_normal_node = DependencyNode(
        id="pkg/generated_types.py",
        file_path="pkg/generated_types.py",
        module_name="pkg.generated_types",
        language="PYTHON",
        loc=600,
        fan_out=2,
        fan_in=1,
        is_god_module=False,
    )
    graph = _make_sample_graph([large_normal_node], [])
    findings = rule.analyze(graph)

    assert len(findings) == 0
    assert large_normal_node.is_god_module is False


# ==============================================================================
# ARC-004: Deep Dependency Chain
# ==============================================================================
def test_arc_004_deep_chain():
    rule = RuleArc004(depth_threshold=5)
    # Create chain of 7 modules (6 hops, exceeding threshold of 5):
    # m0 -> m1 -> m2 -> m3 -> m4 -> m5 -> m6
    modules = [f"pkg/m{i}.py" for i in range(7)]
    nodes = [
        DependencyNode(id=m, file_path=m, module_name=f"pkg.m{i}", language="PYTHON")
        for i, m in enumerate(modules)
    ]
    edges = [
        DependencyEdge(source=modules[i], target=modules[i + 1])
        for i in range(len(modules) - 1)
    ]

    graph = _make_sample_graph(nodes, edges)
    findings = rule.analyze(graph)

    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-004"
    assert findings[0].severity == FindingSeverity.LOW
    assert "6" in findings[0].description


def test_arc_004_normal_shallow_chain():
    rule = RuleArc004(depth_threshold=5)
    # Shallow chain: 3 modules (2 hops)
    modules = ["pkg/a.py", "pkg/b.py", "pkg/c.py"]
    nodes = [
        DependencyNode(id=m, file_path=m, module_name=f"pkg.{m[4]}", language="PYTHON")
        for m in modules
    ]
    edges = [
        DependencyEdge(source="pkg/a.py", target="pkg/b.py"),
        DependencyEdge(source="pkg/b.py", target="pkg/c.py"),
    ]

    graph = _make_sample_graph(nodes, edges)
    findings = rule.analyze(graph)
    assert len(findings) == 0


def test_arc_004_cyclic_graph_with_scc_condensation():
    """Verify that graph with internal SCC cycles condenses cleanly without recursion or errors."""
    rule = RuleArc004(depth_threshold=3)
    # Create a cyclic cluster {scc1, scc2} that cycles, which leads to scc3 -> scc4 -> scc5 -> scc6
    nodes = [
        DependencyNode(id=f"pkg/{name}.py", file_path=f"pkg/{name}.py", module_name=f"pkg.{name}", language="PYTHON")
        for name in ["c1", "c2", "m3", "m4", "m5", "m6"]
    ]
    edges = [
        # Cycle between c1 and c2
        DependencyEdge(source="pkg/c1.py", target="pkg/c2.py"),
        DependencyEdge(source="pkg/c2.py", target="pkg/c1.py"),
        # Directed hops out of the cycle
        DependencyEdge(source="pkg/c2.py", target="pkg/m3.py"),
        DependencyEdge(source="pkg/m3.py", target="pkg/m4.py"),
        DependencyEdge(source="pkg/m4.py", target="pkg/m5.py"),
        DependencyEdge(source="pkg/m5.py", target="pkg/m6.py"),
    ]

    graph = _make_sample_graph(nodes, edges)
    findings = rule.analyze(graph)

    # Condensation collapses {c1, c2} into 1 node, followed by m3 -> m4 -> m5 -> m6 (4 hops > 3 threshold)
    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-004"
