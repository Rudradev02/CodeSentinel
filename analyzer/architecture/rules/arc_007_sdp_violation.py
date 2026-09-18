"""ARC-007: Stable Dependencies Principle (SDP) Violation Rule.

Flags architectural conditions where a stable component (low instability) depends on a volatile component (high instability).
"""

from typing import Optional
from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph

DEFAULT_STABLE_MAX_I = 0.30
DEFAULT_UNSTABLE_MIN_I = 0.70
DEFAULT_MIN_CA = 2


class RuleArc007(BaseArchitectureRule):
    """ARC-007: Stable Dependencies Principle Violation."""

    rule_id = "ARC-007"
    name = "Stable Dependencies Principle Violation"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.MEDIUM
    description = (
        "Detected violation of Robert C. Martin's Stable Dependencies Principle (SDP): "
        "'Depend in the direction of stability'. A highly stable component (relied upon by multiple "
        "subsystems) depends on a volatile, unstable component, compromising its own stability."
    )
    rationale = (
        "When stable foundational components depend on volatile packages, changes in the volatile "
        "package can cascade and force modifications into the stable components and all their dependents."
    )
    remediation = (
        "Apply the Dependency Inversion Principle (DIP): define stable abstract interfaces in the stable "
        "component, and have the volatile component implement or adapt to them."
    )

    def __init__(
        self,
        stable_max_i: float = DEFAULT_STABLE_MAX_I,
        unstable_min_i: float = DEFAULT_UNSTABLE_MIN_I,
        min_ca: int = DEFAULT_MIN_CA,
    ):
        self.stable_max_i = stable_max_i
        self.unstable_min_i = unstable_min_i
        self.min_ca = min_ca

    def analyze(self, graph: ArchitectureGraph, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        if not graph.component_graph or not graph.component_graph.nodes:
            return findings

        cg = graph.component_graph
        nodes_map = {n.id: n for n in cg.nodes}
        edge_map = {e.id: e for e in graph.edges}

        # Check each component edge
        for c_edge in cg.edges:
            src_node = nodes_map.get(c_edge.source)
            tgt_node = nodes_map.get(c_edge.target)

            if not src_node or not tgt_node:
                continue

            src_m = src_node.metrics
            tgt_m = tgt_node.metrics

            # Condition: Source is Stable (I <= stable_max_i and Ca >= min_ca)
            # and Target is Unstable (I >= unstable_min_i)
            is_src_stable = src_m.instability <= self.stable_max_i and src_m.afferent_coupling >= self.min_ca
            is_tgt_unstable = tgt_m.instability >= self.unstable_min_i

            if is_src_stable and is_tgt_unstable:
                # Find first participating file edge for source location
                file_path = src_node.path
                line_start = 1
                sample_import = ""

                if c_edge.file_edges:
                    fe_id = c_edge.file_edges[0]
                    if fe_id in edge_map:
                        fe = edge_map[fe_id]
                        file_path = fe.source
                        line_start = fe.line_number or 1
                        sample_import = f"import {fe.target}"

                location = SourceLocation(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,
                    col_start=0,
                    col_end=None,
                )

                snippet = (
                    f"// Stable Dependencies Principle Violation:\n"
                    f"// {src_node.id} (I={src_m.instability:.2f}, Ca={src_m.afferent_coupling}) -> "
                    f"{tgt_node.id} (I={tgt_m.instability:.2f}, Ca={tgt_m.afferent_coupling})\n"
                    f"{sample_import}"
                ).strip()

                evidence = {
                    "source_component": src_node.id,
                    "source_ca": src_m.afferent_coupling,
                    "source_ce": src_m.efferent_coupling,
                    "source_instability": src_m.instability,
                    "target_component": tgt_node.id,
                    "target_ca": tgt_m.afferent_coupling,
                    "target_ce": tgt_m.efferent_coupling,
                    "target_instability": tgt_m.instability,
                    "thresholds": {
                        "stable_max_instability": self.stable_max_i,
                        "unstable_min_instability": self.unstable_min_i,
                        "min_afferent_coupling": self.min_ca,
                    },
                }

                msg = f"SDP violation: stable '{src_node.id}' depends on volatile '{tgt_node.id}'"
                expl = (
                    f"Component '{src_node.id}' has high architectural stability (I={src_m.instability:.2f}, Ca={src_m.afferent_coupling}) "
                    f"but directly depends on volatile component '{tgt_node.id}' (I={tgt_m.instability:.2f}, Ca={tgt_m.afferent_coupling}). "
                    f"Changes in '{tgt_node.id}' can jeopardize the stability of '{src_node.id}' and its dependents."
                )

                findings.append(
                    self.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=expl,
                        message=msg,
                        explanation=expl,
                        evidence=evidence,
                        confidence_override=FindingConfidence.MEDIUM,
                    )
                )

        # Deterministically sort findings
        findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line_start,
                f.location.col_start or 0,
                f.rule_id,
            )
        )
        return findings
