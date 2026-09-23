"""ARC-009: High-Centrality Architectural Bottleneck / Architectural Mediation Hotspot."""

from typing import Any, Optional
from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class RuleArc009(BaseArchitectureRule):
    """ARC-009: High-Centrality Architectural Bottleneck / Architectural Mediation Hotspot."""

    rule_id = "ARC-009"
    name = "Architectural Bottleneck / High Centrality Component"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.HIGH
    description = (
        "Component lies on a disproportionately high proportion of repository-local shortest dependency "
        "paths, forming an architectural mediation bottleneck. High betweenness centrality indicates that "
        "changes or refactorings in unrelated modules frequently cascade through this central component."
    )
    rationale = (
        "High betweenness centrality creates a structural choke point where many independent subsystems "
        "transitively couple to a single mediation hub. This magnifies blast radius and complicates "
        "independent testing and modular deployment."
    )
    remediation = (
        "Decouple high-traffic communication by applying the Dependency Inversion Principle (DIP), "
        "introducing domain event buses, or decomposing the bottleneck into focused domain interfaces."
    )
    cwe_id = "CWE-1061"
    owasp_category = "A04:2021-Insecure Design"

    def __init__(self, threshold: float = 0.35):
        self.threshold = threshold

    def analyze(
        self,
        graph: ArchitectureGraph,
        threshold: Optional[float] = None,
        **kwargs: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not graph.component_graph or not graph.component_graph.nodes:
            return findings

        active_threshold = threshold if threshold is not None else self.threshold

        # Gate 1: Require at least 5 total components to avoid noise on small repositories
        if graph.component_graph.total_components < 5:
            return findings

        for node in graph.component_graph.nodes:
            # Gate 2: Exclude single-file utility leaves
            if node.metrics.file_count < 2:
                continue

            # Gate 3: Evaluate Betweenness Centrality against threshold
            if node.metrics.betweenness_centrality >= active_threshold:
                rep_file = node.files[0] if node.files else f"{node.path}/__init__.py"
                loc = SourceLocation(
                    file_path=rep_file,
                    line_start=1,
                    line_end=1,
                    col_start=0,
                    col_end=0,
                )

                evidence = {
                    "architecture_risk_category": "HIGH_CENTRALITY",
                    "component_id": node.id,
                    "path": node.path,
                    "betweenness_centrality": node.metrics.betweenness_centrality,
                    "threshold": active_threshold,
                    "in_degree_centrality": node.metrics.in_degree_centrality,
                    "out_degree_centrality": node.metrics.out_degree_centrality,
                    "file_count": node.metrics.file_count,
                }

                msg = (
                    f"Component '{node.id}' lies on a high proportion of repository-local dependency paths "
                    f"(Betweenness Centrality: {node.metrics.betweenness_centrality:.4f} >= {active_threshold}). "
                    f"This creates a systemic architectural mediation hotspot. Consider decoupling high-traffic "
                    f"communication using dependency inversion, domain events, or facade interfaces."
                )

                finding = self.create_finding(
                    location=loc,
                    code_snippet=f"// Architectural Component: {node.id}\n// Path: {node.path}",
                    custom_description=msg,
                    message=msg,
                    evidence=evidence,
                )
                findings.append(finding)

        return findings
