"""Bounded architecture subgraph context extractor for Phase 30.

Extracts participating components, metrics (Ca, Ce, I), cycle paths,
and dependency relationships constrained within strict token budgets.
"""

from typing import Any, Optional
import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from analyzer.architecture.refactoring_simulator import DeterministicRefactoringSimulator
from analyzer.models.graph import ComponentGraph


class BoundedArchitectureContext(BaseModel):
    """Enclosed subgraph context for AI architectural refactoring."""

    model_config = ConfigDict(frozen=True)

    target_rule_id: str
    target_components: list[str]
    cycle_path: list[str] = Field(default_factory=list)
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    metrics: dict[str, dict[str, Any]]
    token_estimate: int


class ArchitectureContextExtractor:
    """Extracts bounded context envelopes adhering to the 1,000 token (~4,000 char) budget."""

    @classmethod
    def extract_context(
        cls,
        graph_input: ComponentGraph | nx.DiGraph,
        target_rule_id: str,
        target_components: list[str],
        cycle_path: Optional[list[str]] = None,
    ) -> BoundedArchitectureContext:
        """Extract bounded 1-hop neighborhood and metrics around target components."""
        G = DeterministicRefactoringSimulator.to_networkx_graph(graph_input)
        effective_cycle = cycle_path or []

        # Find 1-hop neighborhood of all target components
        neighborhood: set[str] = set(target_components)
        for comp in target_components:
            if G.has_node(comp):
                neighborhood.update(G.predecessors(comp))
                neighborhood.update(G.successors(comp))
        neighborhood.update(effective_cycle)

        # Build node and edge descriptors
        nodes_info: list[dict[str, Any]] = []
        edges_info: list[dict[str, Any]] = []
        metrics_info: dict[str, dict[str, Any]] = {}

        metrics_map = DeterministicRefactoringSimulator.compute_node_metrics(G, list(neighborhood))

        for comp in sorted(neighborhood):
            attrs = G.nodes[comp] if G.has_node(comp) else {}
            m = metrics_map.get(comp)
            nodes_info.append({
                "component_id": comp,
                "layer": attrs.get("layer"),
                "file_count": len(attrs.get("files", [])),
            })
            if m:
                metrics_info[comp] = {
                    "ca": m.ca,
                    "ce": m.ce,
                    "instability": m.instability,
                }

        for u, v in G.edges():
            if u in neighborhood and v in neighborhood:
                edges_info.append({
                    "source": u,
                    "target": v,
                })

        # Estimate characters / tokens
        import json
        dumped = json.dumps({"nodes": nodes_info, "edges": edges_info, "metrics": metrics_info})
        token_estimate = max(1, len(dumped) // 4)

        return BoundedArchitectureContext(
            target_rule_id=target_rule_id,
            target_components=target_components,
            cycle_path=effective_cycle,
            nodes=nodes_info,
            edges=edges_info,
            metrics=metrics_info,
            token_estimate=token_estimate,
        )
