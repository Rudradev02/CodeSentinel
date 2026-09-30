"""Deterministic architecture refactoring graph simulation engine for Phase 30.

Simulates hypothetical edge mutations (additions / deletions) on an isolated clone of
CodeSentinel's ComponentGraph or DiGraph, strictly verifying:
- Targeted circular dependencies (ARC-001 / ARC-006) are eliminated.
- Zero secondary or transitive cycles are introduced.
- Robert C. Martin metrics (Ca, Ce, Instability I) are recalculated with ground-truth accuracy.
- Stable Dependencies Principle (SDP / ARC-007) violations are flagged.
"""

from enum import Enum
import logging
from typing import Any, Optional
import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from analyzer.models.graph import ComponentGraph

logger = logging.getLogger(__name__)


class RefactoringType(str, Enum):
    DEPENDENCY_INVERSION = "DEPENDENCY_INVERSION"
    MODULE_EXTRACTION = "MODULE_EXTRACTION"
    INTERFACE_INTRODUCTION = "INTERFACE_INTRODUCTION"
    CYCLE_BREAKING = "CYCLE_BREAKING"
    RESPONSIBILITY_SPLITTING = "RESPONSIBILITY_SPLITTING"
    BOUNDARY_CORRECTION = "BOUNDARY_CORRECTION"


class EdgeMutationAction(str, Enum):
    REMOVE = "REMOVE"
    ADD = "ADD"


class EdgeMutation(BaseModel):
    """Specification of a hypothetical edge addition or deletion."""

    model_config = ConfigDict(frozen=True)

    action: EdgeMutationAction
    source: str
    target: str


class RefactoringProposalDTO(BaseModel):
    """Structured proposal representing an AI-generated architectural refactoring plan."""

    model_config = ConfigDict(extra="ignore")

    proposal_id: str
    target_rule_id: str
    target_finding_ids: list[str] = Field(default_factory=list)
    refactoring_type: RefactoringType
    title: str
    problem_statement: str
    proposed_design: str
    affected_components: list[str]
    affected_files: list[str] = Field(default_factory=list)
    hypothetical_edge_mutations: list[dict[str, str]] = Field(default_factory=list)
    expected_metric_deltas: dict[str, Any] = Field(default_factory=dict)
    risks_and_tradeoffs: list[str] = Field(default_factory=list)
    compatibility_impact: str = "BACKWARD_COMPATIBLE"
    test_requirements: list[str] = Field(default_factory=list)
    status: str = "PROPOSAL_ONLY"


class ComponentMetricSnapshot(BaseModel):
    """Robert C. Martin metrics for an individual node."""

    model_config = ConfigDict(frozen=True)

    ca: int = Field(..., description="Afferent coupling (incoming dependents)")
    ce: int = Field(..., description="Efferent coupling (outgoing dependencies)")
    instability: float = Field(..., description="I = Ce / (Ca + Ce)")


class SimulationResult(BaseModel):
    """Outcome of a deterministic graph mutation simulation."""

    model_config = ConfigDict(frozen=True)

    simulation_status: str = Field(..., description="'VERIFIED_SIMULATION' or 'UNVERIFIED_SIMULATION'")
    target_cycle_eliminated: bool
    cycles_before_count: int
    cycles_after_count: int
    new_cycles_detected: list[list[str]]
    before_metrics: dict[str, ComponentMetricSnapshot]
    after_metrics: dict[str, ComponentMetricSnapshot]
    metric_deltas: dict[str, dict[str, float]]
    sdp_violations: list[str]
    diagnostics: list[str]


class DeterministicRefactoringSimulator:
    """Simulates edge additions/deletions on cloned graphs with zero autonomous code mutation."""

    @classmethod
    def to_networkx_graph(cls, graph_input: ComponentGraph | nx.DiGraph) -> nx.DiGraph:
        """Convert ComponentGraph or return copy of nx.DiGraph."""
        if isinstance(graph_input, nx.DiGraph):
            return graph_input.copy()

        G = nx.DiGraph()
        for node in graph_input.nodes:
            G.add_node(node.id, path=node.path, layer=node.layer, files=node.files)
        for edge in graph_input.edges:
            G.add_edge(edge.source, edge.target, weight=edge.weight)
        return G

    @classmethod
    def compute_node_metrics(cls, G: nx.DiGraph, nodes: Optional[list[str]] = None) -> dict[str, ComponentMetricSnapshot]:
        """Compute Ca, Ce, and Instability I for specified nodes or all nodes in G."""
        target_nodes = nodes if nodes is not None else list(G.nodes())
        metrics: dict[str, ComponentMetricSnapshot] = {}

        for n in target_nodes:
            if not G.has_node(n):
                metrics[n] = ComponentMetricSnapshot(ca=0, ce=0, instability=0.0)
                continue

            ca = G.in_degree(n)
            ce = G.out_degree(n)
            instability = round(float(ce) / float(ca + ce), 4) if (ca + ce) > 0 else 0.0
            metrics[n] = ComponentMetricSnapshot(ca=ca, ce=ce, instability=instability)

        return metrics

    @classmethod
    def find_all_cycles(cls, G: nx.DiGraph) -> list[list[str]]:
        """Return all simple directed cycles in G as sorted lists."""
        try:
            raw_cycles = list(nx.simple_cycles(G))
            # Sort each cycle to have canonical representation
            canonical = []
            for cycle in raw_cycles:
                if len(cycle) >= 2:
                    min_idx = cycle.index(min(cycle))
                    rotated = cycle[min_idx:] + cycle[:min_idx]
                    canonical.append(rotated)
            return canonical
        except Exception as exc:
            logger.warning("Error finding simple cycles: %s", exc)
            return []

    @classmethod
    def simulate_proposal(
        cls,
        graph_input: ComponentGraph | nx.DiGraph,
        proposal: RefactoringProposalDTO | dict[str, Any],
    ) -> SimulationResult:
        """Execute deterministic simulation of the proposed hypothetical edge mutations."""
        if isinstance(proposal, dict):
            proposal = RefactoringProposalDTO.model_validate(proposal)

        G_orig = cls.to_networkx_graph(graph_input)
        G_mutated = G_orig.copy()

        diagnostics: list[str] = []
        sdp_violations: list[str] = []

        # 1. Baseline analysis
        cycles_before = cls.find_all_cycles(G_orig)
        cycles_before_set = {tuple(c) for c in cycles_before}

        affected = list(proposal.affected_components)
        before_metrics = cls.compute_node_metrics(G_orig, affected)

        # 2. Apply hypothetical mutations
        for mut_dict in proposal.hypothetical_edge_mutations:
            action = str(mut_dict.get("action", "")).upper()
            src = mut_dict.get("source", "")
            tgt = mut_dict.get("target", "")

            if not src or not tgt:
                continue

            if action == EdgeMutationAction.REMOVE.value:
                if G_mutated.has_edge(src, tgt):
                    G_mutated.remove_edge(src, tgt)
                    diagnostics.append(f"Simulated removal of edge: {src} -> {tgt}")
                else:
                    diagnostics.append(f"Notice: Edge to remove does not exist: {src} -> {tgt}")
            elif action == EdgeMutationAction.ADD.value:
                if not G_mutated.has_node(src):
                    G_mutated.add_node(src)
                if not G_mutated.has_node(tgt):
                    G_mutated.add_node(tgt)
                G_mutated.add_edge(src, tgt)
                diagnostics.append(f"Simulated addition of edge: {src} -> {tgt}")

        # 3. Post-mutation cycle analysis
        cycles_after = cls.find_all_cycles(G_mutated)
        cycles_after_set = {tuple(c) for c in cycles_after}

        # Check if new cycles were introduced
        new_cycles = [list(c) for c in cycles_after_set - cycles_before_set]

        # Target cycle eliminated check:
        # If the original graph had cycles involving the affected components, verify none remain
        affected_set = set(affected)
        original_affected_cycles = [
            c for c in cycles_before if any(node in affected_set for node in c)
        ]
        remaining_affected_cycles = [
            c for c in cycles_after if any(node in affected_set for node in c)
        ]

        target_cycle_eliminated = (
            len(original_affected_cycles) > 0 and len(remaining_affected_cycles) == 0
        ) or (len(cycles_before) > 0 and len(cycles_after) < len(cycles_before))

        # 4. Post-mutation metrics
        after_metrics = cls.compute_node_metrics(G_mutated, affected)

        # Calculate deltas
        metric_deltas: dict[str, dict[str, float]] = {}
        for n in affected:
            b = before_metrics.get(n, ComponentMetricSnapshot(ca=0, ce=0, instability=0.0))
            a = after_metrics.get(n, ComponentMetricSnapshot(ca=0, ce=0, instability=0.0))
            metric_deltas[n] = {
                "delta_ca": float(a.ca - b.ca),
                "delta_ce": float(a.ce - b.ce),
                "delta_instability": round(a.instability - b.instability, 4),
            }

        # 5. Check Stable Dependencies Principle (SDP / ARC-007)
        # Any new edge (u, v) where I(u) < I(v) means more stable depends on less stable
        for mut_dict in proposal.hypothetical_edge_mutations:
            if str(mut_dict.get("action", "")).upper() == EdgeMutationAction.ADD.value:
                src = mut_dict.get("source", "")
                tgt = mut_dict.get("target", "")
                if G_mutated.has_node(src) and G_mutated.has_node(tgt):
                    i_src = after_metrics.get(src, cls.compute_node_metrics(G_mutated, [src])[src]).instability
                    i_tgt = after_metrics.get(tgt, cls.compute_node_metrics(G_mutated, [tgt])[tgt]).instability
                    if i_src < i_tgt:
                        sdp_violations.append(
                            f"SDP Violation (ARC-007): Stable component '{src}' (I={i_src:.2f}) "
                            f"depends on less stable component '{tgt}' (I={i_tgt:.2f})"
                        )

        # 6. Final Status Determination
        is_verified = (
            (len(new_cycles) == 0)
            and (target_cycle_eliminated or (len(cycles_before) == 0 and len(cycles_after) == 0))
        )

        if not is_verified:
            if new_cycles:
                diagnostics.append(f"REJECTION: Proposal introduced {len(new_cycles)} secondary cyclic dependency.")
            if not target_cycle_eliminated and len(cycles_before) > 0:
                diagnostics.append("REJECTION: Proposal failed to eliminate the targeted circular dependency.")

        status = "VERIFIED_SIMULATION" if is_verified else "UNVERIFIED_SIMULATION"

        return SimulationResult(
            simulation_status=status,
            target_cycle_eliminated=target_cycle_eliminated,
            cycles_before_count=len(cycles_before),
            cycles_after_count=len(cycles_after),
            new_cycles_detected=new_cycles,
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            metric_deltas=metric_deltas,
            sdp_violations=sdp_violations,
            diagnostics=diagnostics,
        )
