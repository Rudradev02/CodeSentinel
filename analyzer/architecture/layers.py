"""Architectural tier classification and layer boundary inversion detection.

Maps components to canonical architectural tiers and flags prohibited downward-to-upward
dependencies (e.g., INFRASTRUCTURE -> PRESENTATION, DOMAIN -> INFRASTRUCTURE).
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from analyzer.models.graph import ComponentGraph, DependencyEdge


class ArchitecturalTier(str, Enum):
    """Canonical architectural tiers."""
    PRESENTATION = "PRESENTATION"
    APPLICATION = "APPLICATION"
    DOMAIN = "DOMAIN"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    UTILITY = "UTILITY"


# Ordered keywords for heuristic tier inference
TIER_PATTERNS: dict[ArchitecturalTier, list[str]] = {
    ArchitecturalTier.PRESENTATION: [
        "presentation", "presentations", "presenter", "presenters",
        "api", "controller", "controllers", "endpoint", "endpoints",
        "route", "routes", "view", "views", "cli", "reporting", "frontend", "ui",
    ],
    ArchitecturalTier.INFRASTRUCTURE: [
        "infrastructure", "infra",
        "db", "database", "persistence", "repository", "repositories",
        "adapter", "adapters", "storage", "client", "clients",
    ],
    ArchitecturalTier.DOMAIN: [
        "domain", "domains",
        "model", "models", "entity", "entities", "rule", "rules", "core",
    ],
    ArchitecturalTier.APPLICATION: [
        "application", "app", "usecases", "usecase", "handler", "handlers",
        "service", "services", "use_case", "use_cases", "workflow", "orchestrator", "engine",
    ],
    ArchitecturalTier.UTILITY: [
        "util", "utils", "common", "helper", "helpers", "config", "shared",
    ],
}

# Explicit prohibited dependency relationships (source_tier -> target_tier)
# Derives from Clean Architecture & Hexagonal Architecture principles
DEFAULT_PROHIBITED_DEPENDENCIES: set[tuple[str, str]] = {
    (ArchitecturalTier.INFRASTRUCTURE.value, ArchitecturalTier.PRESENTATION.value),
    (ArchitecturalTier.INFRASTRUCTURE.value, ArchitecturalTier.APPLICATION.value),
    (ArchitecturalTier.DOMAIN.value, ArchitecturalTier.PRESENTATION.value),
    (ArchitecturalTier.DOMAIN.value, ArchitecturalTier.INFRASTRUCTURE.value),
    (ArchitecturalTier.UTILITY.value, ArchitecturalTier.PRESENTATION.value),
    (ArchitecturalTier.UTILITY.value, ArchitecturalTier.APPLICATION.value),
}


class LayerBoundaryViolation(BaseModel):
    """Structured record of an architectural layer boundary inversion."""
    source_component: str
    source_tier: str
    target_component: str
    target_tier: str
    prohibited_rule: str
    violating_file_edges: list[DependencyEdge] = Field(default_factory=list)


class LayerBoundaryAnalyzer:
    """Classifies component architectural tiers and detects illegal layer boundary inversions."""

    def __init__(
        self,
        explicit_mappings: Optional[dict[str, str]] = None,
        prohibited_dependencies: Optional[set[tuple[str, str]]] = None,
    ):
        self.explicit_mappings = explicit_mappings or {}
        self.prohibited_dependencies = prohibited_dependencies or DEFAULT_PROHIBITED_DEPENDENCIES

    def infer_tier(self, component_id: str, component_path: str) -> Optional[str]:
        """Infer architectural tier from component ID and directory path.
        
        Explicit mappings take precedence. If no keyword matches, returns None.
        Unknown tiers are never guessed.
        """
        # 1. Check explicit mappings
        if component_id in self.explicit_mappings:
            mapped = self.explicit_mappings[component_id].upper()
            try:
                return ArchitecturalTier(mapped).value
            except ValueError:
                return None

        # 2. Heuristic keyword pattern matching from deepest part to shallowest
        parts = component_id.split(".")
        for part in reversed(parts):
            clean_part = part.lower().replace("-", "_")
            for tier, keywords in TIER_PATTERNS.items():
                if clean_part in keywords:
                    return tier.value

        # Path-based fallback check
        path_segments = [p.lower().replace("-", "_") for p in component_path.split("/")]
        for segment in reversed(path_segments):
            for tier, keywords in TIER_PATTERNS.items():
                if segment in keywords:
                    return tier.value

        return None

    def classify_components(self, component_graph: ComponentGraph) -> None:
        """Populate the layer attribute on all ComponentNodes in place."""
        for node in component_graph.nodes:
            node.layer = self.infer_tier(node.id, node.path)

    def find_inversions(
        self,
        component_graph: ComponentGraph,
        file_edges: list[DependencyEdge],
    ) -> list[LayerBoundaryViolation]:
        """Detect prohibited layer boundary inversions across component edges.
        
        Args:
            component_graph: Populated component graph with classified layers.
            file_edges: All file-level dependency edges for evidence extraction.
            
        Returns:
            Sorted list of LayerBoundaryViolation records.
        """
        # Build node layer lookup
        comp_layers: dict[str, Optional[str]] = {n.id: n.layer for n in component_graph.nodes}
        
        # Build file edge ID lookup: (source_comp, target_comp) -> file edges
        edge_map: dict[str, DependencyEdge] = {e.id: e for e in file_edges}

        violations: list[LayerBoundaryViolation] = []

        for c_edge in component_graph.edges:
            src_tier = comp_layers.get(c_edge.source)
            tgt_tier = comp_layers.get(c_edge.target)

            # Both components must have known layers to determine inversion
            if not src_tier or not tgt_tier:
                continue

            if (src_tier, tgt_tier) in self.prohibited_dependencies:
                violating_file_edges = [
                    edge_map[eid] for eid in c_edge.file_edges if eid in edge_map
                ]
                # Sort violating file edges deterministically
                violating_file_edges.sort(
                    key=lambda fe: (fe.source, fe.line_number or 0, fe.target)
                )

                rule_desc = f"{src_tier} -> {tgt_tier}"
                violations.append(
                    LayerBoundaryViolation(
                        source_component=c_edge.source,
                        source_tier=src_tier,
                        target_component=c_edge.target,
                        target_tier=tgt_tier,
                        prohibited_rule=rule_desc,
                        violating_file_edges=violating_file_edges,
                    )
                )

        violations.sort(key=lambda v: (v.source_component, v.target_component))
        return violations


def classify_component_layer(component_id: str, component_path: str = "") -> Optional[ArchitecturalTier]:
    """Helper function to infer component tier directly."""
    tier_str = LayerBoundaryAnalyzer().infer_tier(component_id, component_path)
    if tier_str:
        return ArchitecturalTier(tier_str)
    return None
