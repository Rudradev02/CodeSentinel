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
    CONTROLLER = "CONTROLLER"
    SERVICE = "SERVICE"


class ContractEdgeType(str, Enum):
    CALL = "CALL"
    COMPOSED_CALL = "COMPOSED_CALL"
    GUARANTEE_TO_REQUIREMENT = "GUARANTEE_TO_REQUIREMENT"
    FIELD_TRANSFER = "FIELD_TRANSFER"
    RETURN_ALIAS = "RETURN_ALIAS"
    EXCEPTION_FLOW = "EXCEPTION_FLOW"


class ContractGraphNode(BaseModel):
    id: str = ""
    name: str = ""
    contract_id: str = ""
    qualified_name: str = ""
    node_type: ContractNodeType = ContractNodeType.FUNCTION
    file_path: str = ""
    line: int = 0
    contract_hash: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id and self.contract_id:
            self.id = self.contract_id
        if not self.contract_id and self.id:
            self.contract_id = self.id
        if not self.name and self.qualified_name:
            self.name = self.qualified_name
        if not self.qualified_name and self.name:
            self.qualified_name = self.name


class ContractGraphEdge(BaseModel):
    source_id: str = ""
    target_id: str = ""
    source_contract_id: str = ""
    target_contract_id: str = ""
    edge_type: ContractEdgeType
    compatibility: CompatibilityState = CompatibilityState.UNKNOWN
    call_site: str = ""
    composition_depth: int = 0
    details: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.source_id and self.source_contract_id:
            self.source_id = self.source_contract_id
        if not self.source_contract_id and self.source_id:
            self.source_contract_id = self.source_id
        if not self.target_id and self.target_contract_id:
            self.target_id = self.target_contract_id
        if not self.target_contract_id and self.target_id:
            self.target_contract_id = self.target_id


class ProjectContractGraph(BaseModel):
    """In-memory directed contract dependency graph for the repository."""
    nodes: dict[str, ContractGraphNode] = Field(default_factory=dict)
    edges: list[ContractGraphEdge] = Field(default_factory=list)
    max_nodes: int = 5000

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def add_node(self, node: ContractGraphNode) -> bool:
        if len(self.nodes) < self.max_nodes:
            self.nodes[node.id] = node
            return True
        return False

    def add_edge(self, edge: Optional[ContractGraphEdge] = None, **kwargs: Any) -> Optional[ContractGraphEdge]:
        if edge is None:
            edge = ContractGraphEdge(**kwargs)
        self.edges.append(edge)
        return edge

    def to_summary_dict(self) -> dict[str, Any]:
        """Produce deterministic summary metrics for reporting and persistence."""
        comp_counts: dict[str, int] = {}
        for e in self.edges:
            comp_counts[e.compatibility.value] = comp_counts.get(e.compatibility.value, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_contract_nodes": len(self.nodes),
            "total_contract_edges": len(self.edges),
            "satisfied_edges": comp_counts.get(CompatibilityState.SATISFIED.value, 0),
            "violated_edges": comp_counts.get(CompatibilityState.VIOLATED.value, 0),
            "conflicting_edges": comp_counts.get(CompatibilityState.CONFLICTING.value, 0),
            "unknown_edges": comp_counts.get(CompatibilityState.UNKNOWN.value, 0),
            "nodes_truncated": len(self.nodes) >= self.max_nodes,
        }
