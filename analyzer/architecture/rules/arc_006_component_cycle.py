"""ARC-006: Component Circular Dependency Group Rule.

Detects circular dependency groups among directory packages using Strongly Connected Components (SCC).
"""

import uuid
import networkx as nx

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class RuleArc006(BaseArchitectureRule):
    """ARC-006: Component-Level Circular Dependency Group."""

    rule_id = "ARC-006"
    name = "Component Circular Dependency Group"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    description = (
        "Detected circular dependency group between two or more architectural components/packages. "
        "Component-level circular dependencies tightly couple subsystems across multiple files, "
        "preventing independent deployment, compilation, and isolated unit testing."
    )
    rationale = (
        "Circular dependencies between subsystems break modular boundaries and architectural hierarchies, "
        "causing ripple effects during refactoring and complicating system comprehension."
    )
    remediation = (
        "Break the component cycle by extracting shared domain models/interfaces into an independent leaf component, "
        "or applying event-driven decoupling / dependency injection."
    )

    def analyze(self, graph: ArchitectureGraph, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        if not graph.component_graph or not graph.component_graph.nodes:
            return findings

        cg = graph.component_graph

        # Build directed graph from component edges
        G_c = nx.DiGraph()
        for node in cg.nodes:
            G_c.add_node(node.id)

        for edge in cg.edges:
            G_c.add_edge(edge.source, edge.target, weight=edge.weight)

        # Compute strongly connected components (SCC)
        try:
            sccs = list(nx.strongly_connected_components(G_c))
        except Exception:
            return findings

        # Filter SCCs with at least 2 components
        cycle_sccs = [scc for scc in sccs if len(scc) >= 2]
        # Sort SCCs deterministically by their smallest component ID
        cycle_sccs.sort(key=lambda scc: sorted(list(scc))[0])

        for scc in cycle_sccs:
            canonical_components = sorted(list(scc))
            group_key = ",".join(canonical_components)

            # Dedicated deterministic finding ID without fabricating line numbers
            finding_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"ARC-006|{group_key}"))

            # Primary directory coordinate
            first_comp = canonical_components[0]
            dir_path = first_comp.replace(".", "/")

            location = SourceLocation(
                file_path=dir_path,
                line_start=1,
                line_end=None,
                col_start=0,
                col_end=None,
            )

            # Collect participating inter-component edges
            participating_edges = []
            for u in canonical_components:
                for v in canonical_components:
                    if G_c.has_edge(u, v):
                        participating_edges.append({
                            "source": u,
                            "target": v,
                            "weight": G_c[u][v].get("weight", 1),
                        })
            participating_edges.sort(key=lambda e: (e["source"], e["target"]))

            cycle_str = " <-> ".join(canonical_components)
            snippet = f"// Component Circular Dependency Group ({len(canonical_components)} components):\n// {cycle_str}"

            evidence = {
                "scc_components": canonical_components,
                "cycle_components": canonical_components,
                "component_count": len(canonical_components),
                "participating_edges": participating_edges,
            }

            msg = f"Component circular dependency group ({len(canonical_components)} components)"
            expl = (
                f"Detected strongly connected circular dependency group across {len(canonical_components)} "
                f"components: [{', '.join(canonical_components)}]. Subsystems are coupled bidirectionally."
            )

            findings.append(
                self.create_finding(
                    location=location,
                    code_snippet=snippet,
                    custom_description=expl,
                    message=msg,
                    explanation=expl,
                    evidence=evidence,
                    finding_id_override=finding_id,
                )
            )

        return findings
