"""ARC-005: Layer Boundary Inversion Rule.

Detects prohibited downward-to-upward architectural tier dependencies (e.g. INFRASTRUCTURE -> PRESENTATION).
"""

from typing import Optional
from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.architecture.layers import LayerBoundaryAnalyzer
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class RuleArc005(BaseArchitectureRule):
    """ARC-005: Layer Boundary Inversion."""

    rule_id = "ARC-005"
    name = "Layer Boundary Inversion"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.MEDIUM
    description = (
        "Detected architectural layer boundary inversion where a lower-tier component "
        "directly depends on a higher-tier or prohibited component (e.g. persistence depending on controllers, "
        "or domain entities depending on storage adapters)."
    )
    rationale = (
        "Clean architecture mandates that dependencies point in the direction of stability and abstraction. "
        "Lower-tier persistence and domain modules must remain decoupled from presentation and infrastructure adapters."
    )
    remediation = (
        "Invert the dependency using the Dependency Inversion Principle (DIP): define an interface in the "
        "higher-level module and implement it in the lower-level module, or move shared definitions to a domain layer."
    )

    def __init__(self, layer_analyzer: Optional[LayerBoundaryAnalyzer] = None):
        self.layer_analyzer = layer_analyzer or LayerBoundaryAnalyzer()

    def analyze(self, graph: ArchitectureGraph, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        if not graph.component_graph or not graph.component_graph.nodes:
            return findings

        # Classify components if not already classified
        self.layer_analyzer.classify_components(graph.component_graph)

        violations = self.layer_analyzer.find_inversions(
            graph.component_graph,
            file_edges=graph.edges,
        )

        for v in violations:
            # Pick first violating file edge for source location
            file_path = f"{v.source_component.replace('.', '/')}"
            line_start = 1
            sample_import = ""

            if v.violating_file_edges:
                first_edge = v.violating_file_edges[0]
                file_path = first_edge.source
                line_start = first_edge.line_number or 1
                sample_import = f"import {first_edge.target}"

            location = SourceLocation(
                file_path=file_path,
                line_start=line_start,
                line_end=line_start,
                col_start=0,
                col_end=None,
            )

            code_snippet = (
                f"// Layer Boundary Inversion:\n"
                f"// {v.source_component} ({v.source_tier}) -> {v.target_component} ({v.target_tier})\n"
                f"{sample_import}"
            ).strip()

            evidence = {
                "source_component": v.source_component,
                "source_tier": v.source_tier,
                "target_component": v.target_component,
                "target_tier": v.target_tier,
                "prohibited_rule": v.prohibited_rule,
                "rule_description": v.prohibited_rule,
                "violating_imports_count": len(v.violating_file_edges),
                "violating_targets": sorted(list({e.target for e in v.violating_file_edges})),
            }

            msg = f"Layer boundary inversion: {v.source_tier} -> {v.target_tier}"
            expl = (
                f"Component '{v.source_component}' ({v.source_tier}) directly depends on "
                f"'{v.target_component}' ({v.target_tier}), violating the prohibited architectural "
                f"boundary relationship [{v.prohibited_rule}]."
            )

            findings.append(
                self.create_finding(
                    location=location,
                    code_snippet=code_snippet,
                    custom_description=expl,
                    message=msg,
                    explanation=expl,
                    evidence=evidence,
                    confidence_override=FindingConfidence.MEDIUM,
                )
            )

        return findings
