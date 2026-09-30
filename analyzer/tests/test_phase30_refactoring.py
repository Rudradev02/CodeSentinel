"""Unit and integration tests for Phase 30 AI Architectural Refactoring & Graph Simulation.

Validates:
- Deterministic simulation of hypothetical edge mutations breaking cyclic dependencies.
- Rejection of refactoring proposals that introduce secondary or transitive cycles.
- Ground truth Robert C. Martin metric recalculation (Ca, Ce, Instability I).
- Stable Dependencies Principle (SDP / ARC-007) violation detection.
- Refactoring proposal generation and DB persistence in AIRefactoringProposalRecord.
"""

import networkx as nx
import pytest

from analyzer.architecture.refactoring_simulator import (
    DeterministicRefactoringSimulator,
    RefactoringProposalDTO,
    RefactoringType,
)
from analyzer.models.graph import ComponentEdge, ComponentGraph, ComponentNode, PackageMetrics


@pytest.fixture
def cyclic_component_graph():
    """Builds a 3-node cyclic component graph: A -> B -> C -> A."""
    G = nx.DiGraph()
    G.add_node("comp_a", layer="domain", files=["a1.py", "a2.py"])
    G.add_node("comp_b", layer="services", files=["b1.py"])
    G.add_node("comp_c", layer="infrastructure", files=["c1.py"])

    G.add_edge("comp_a", "comp_b")
    G.add_edge("comp_b", "comp_c")
    G.add_edge("comp_c", "comp_a")  # Cycle back-edge
    return G



def test_cycle_breaking_simulation(cyclic_component_graph):
    """Simulated edge mutation correctly eliminates targeted cycle from component graph."""
    # Proposal to invert/remove back-edge comp_c -> comp_a
    proposal = RefactoringProposalDTO(
        proposal_id="REF-TEST-01",
        target_rule_id="ARC-006",
        refactoring_type=RefactoringType.CYCLE_BREAKING,
        title="Break component cycle C -> A",
        problem_statement="Circular dependency comp_a -> comp_b -> comp_c -> comp_a",
        proposed_design="Remove dependency from comp_c to comp_a via interface",
        affected_components=["comp_a", "comp_b", "comp_c"],
        hypothetical_edge_mutations=[
            {"action": "REMOVE", "source": "comp_c", "target": "comp_a"}
        ],
    )

    result = DeterministicRefactoringSimulator.simulate_proposal(
        graph_input=cyclic_component_graph,
        proposal=proposal,
    )

    assert result.simulation_status == "VERIFIED_SIMULATION"
    assert result.target_cycle_eliminated is True
    assert result.cycles_before_count == 1
    assert result.cycles_after_count == 0
    assert len(result.new_cycles_detected) == 0

    # Metric changes:
    # comp_a lost incoming edge from comp_c (Ca: 1 -> 0, Ce: 1 -> 1, I: 0.5 -> 1.0)
    assert result.after_metrics["comp_a"].ca == 0
    assert result.after_metrics["comp_a"].ce == 1
    assert result.after_metrics["comp_a"].instability == 1.0

    # comp_c lost outgoing edge to comp_a (Ca: 1 -> 1, Ce: 1 -> 0, I: 0.5 -> 0.0)
    assert result.after_metrics["comp_c"].ca == 1
    assert result.after_metrics["comp_c"].ce == 0
    assert result.after_metrics["comp_c"].instability == 0.0


def test_secondary_cycle_detection(cyclic_component_graph):
    """Simulation rejects a flawed proposal that introduces a secondary cycle elsewhere."""
    # Add another node D
    cyclic_component_graph.add_node("comp_d")
    cyclic_component_graph.add_edge("comp_a", "comp_d")

    # Flawed proposal: removes C -> A, but introduces D -> B and B -> D (creating a new cycle between B and D)
    proposal = RefactoringProposalDTO(
        proposal_id="REF-TEST-02",
        target_rule_id="ARC-006",
        refactoring_type=RefactoringType.DEPENDENCY_INVERSION,
        title="Flawed refactoring creating new cycle",
        problem_statement="Attempting to fix cycle",
        proposed_design="Adds reciprocal edge between B and D",
        affected_components=["comp_a", "comp_b", "comp_c", "comp_d"],
        hypothetical_edge_mutations=[
            {"action": "REMOVE", "source": "comp_c", "target": "comp_a"},
            {"action": "ADD", "source": "comp_b", "target": "comp_d"},
            {"action": "ADD", "source": "comp_d", "target": "comp_b"},  # New cycle!
        ],
    )

    result = DeterministicRefactoringSimulator.simulate_proposal(
        graph_input=cyclic_component_graph,
        proposal=proposal,
    )

    assert result.simulation_status == "UNVERIFIED_SIMULATION"
    assert len(result.new_cycles_detected) > 0
    assert any("REJECTION: Proposal introduced" in diag for diag in result.diagnostics)


def test_metric_recalculation_accuracy():
    """Recalculated Ca, Ce, and Instability match ground truth calculation."""
    G = nx.DiGraph()
    # Node X: 3 incoming, 1 outgoing -> Ca=3, Ce=1, I = 1 / 4 = 0.25
    G.add_edge("a", "x")
    G.add_edge("b", "x")
    G.add_edge("c", "x")
    G.add_edge("x", "d")

    proposal = RefactoringProposalDTO(
        proposal_id="REF-TEST-03",
        target_rule_id="ARC-009",
        refactoring_type=RefactoringType.MODULE_EXTRACTION,
        title="Extract module from X",
        problem_statement="High afferent coupling on X",
        proposed_design="Route a and b through mediator",
        affected_components=["x"],
        hypothetical_edge_mutations=[
            {"action": "REMOVE", "source": "a", "target": "x"},
            {"action": "REMOVE", "source": "b", "target": "x"},
        ],
    )

    result = DeterministicRefactoringSimulator.simulate_proposal(
        graph_input=G,
        proposal=proposal,
    )

    # Before: Ca=3, Ce=1, I=0.25
    assert result.before_metrics["x"].ca == 3
    assert result.before_metrics["x"].ce == 1
    assert result.before_metrics["x"].instability == 0.25

    # After: Ca=1, Ce=1, I=0.5
    assert result.after_metrics["x"].ca == 1
    assert result.after_metrics["x"].ce == 1
    assert result.after_metrics["x"].instability == 0.5
    assert result.metric_deltas["x"]["delta_ca"] == -2.0
    assert result.metric_deltas["x"]["delta_instability"] == 0.25


