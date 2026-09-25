"""Project Contract Graph (PCG) data structures and builder (Phase 20).

Provides an in-memory, repository-local directed graph representing all
interprocedural contract dependencies, boundaries, and composition links.
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.contracts.composition import CompatibilityState


class ContractNodeType(str, Enum):
    FUNCTION = "FUNCTION"
    CONTRACT = "CONTRACT"
    BOUNDARY = "BOUNDARY"


class ContractEdgeType(str, Enum):
    CALL = "CALL"
    GUARANTEE_TO_REQUIREMENT = "GUARANTEE_TO_REQUIREMENT"
    FIELD_TRANSFER = "FIELD_TRANSFER"
    RETURN_ALIAS = "RETURN_ALIAS"
    EXCEPTION_FLOW = "EXCEPTION_FLOW"


class ContractGraphNode(BaseModel):
    id: str
    name: str
    node_type: ContractNodeType
    file_path: str = ""
    line: int = 0
    contract_hash: Optional[str] = None


class ContractGraphEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: ContractEdgeType
    compatibility: CompatibilityState = CompatibilityState.UNKNOWN
    details: str = ""


class ProjectContractGraph(BaseModel):
    """In-memory directed contract dependency graph for the repository."""
    nodes: dict[str, ContractGraphNode] = Field(default_factory=dict)
    edges: list[ContractGraphEdge] = Field(default_factory=list)
    max_nodes: int = 5000

    def add_node(self, node: ContractGraphNode) -> None:
        if len(self.nodes) < self.max_nodes:
            self.nodes[node.id] = node

    def add_edge(self, edge: ContractGraphEdge) -> None:
        self.edges.append(edge)

    def to_summary_dict(self) -> dict[str, Any]:
        """Produce deterministic summary metrics for reporting and persistence."""
        comp_counts: dict[str, int] = {}
        for e in self.edges:
            comp_counts[e.compatibility.value] = comp_counts.get(e.compatibility.value, 0) + 1

        return {
            "total_contract_nodes": len(self.nodes),
            "total_contract_edges": len(self.edges),
            "satisfied_edges": comp_counts.get(CompatibilityState.SATISFIED.value, 0),
            "violated_edges": comp_counts.get(CompatibilityState.VIOLATED.value, 0),
            "conflicting_edges": comp_counts.get(CompatibilityState.CONFLICTING.value, 0),
            "unknown_edges": comp_counts.get(CompatibilityState.UNKNOWN.value, 0),
        }
