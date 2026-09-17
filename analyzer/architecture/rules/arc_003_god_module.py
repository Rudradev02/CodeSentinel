"""ARC-003: God Module Architectural Smell."""

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class RuleArc003(BaseArchitectureRule):
    """ARC-003: God Module Architectural Smell."""

    rule_id = "ARC-003"
    name = "God Module Structural Smell"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.MEDIUM
    description = (
        "Detected potential 'God Module' combining high lines of code, high afferent coupling (fan-in), "
        "and high efferent coupling (fan-out). A module serving as a central hub for disproportionate "
        "logic and dependencies represents an architectural bottleneck with elevated maintenance risk."
    )
    rationale = (
        "A heuristic structural architecture smell based on LOC and coupling metrics indicating concentrated "
        "systemic complexity and high change friction. This is a structural heuristic, not a semantic proof of design flaw."
    )
    remediation = (
        "Decompose this module according to the Single Responsibility Principle. Identify independent "
        "sub-domains and extract them into separate, focused services or utility modules."
    )

    def __init__(
        self,
        loc_threshold_1: int = 500,
        fan_out_threshold_1: int = 8,
        fan_in_threshold_1: int = 5,
        loc_threshold_2: int = 800,
        fan_out_threshold_2: int = 10,
    ):
        self.loc_threshold_1 = loc_threshold_1
        self.fan_out_threshold_1 = fan_out_threshold_1
        self.fan_in_threshold_1 = fan_in_threshold_1
        self.loc_threshold_2 = loc_threshold_2
        self.fan_out_threshold_2 = fan_out_threshold_2

    def analyze(self, graph: ArchitectureGraph) -> list[Finding]:
        findings: list[Finding] = []

        for node in graph.nodes:
            if node.is_external:
                continue

            matches_cond_1 = (
                node.loc > self.loc_threshold_1
                and node.fan_out > self.fan_out_threshold_1
                and node.fan_in > self.fan_in_threshold_1
            )
            matches_cond_2 = (
                node.loc > self.loc_threshold_2
                and node.fan_out > self.fan_out_threshold_2
            )

            if matches_cond_1 or matches_cond_2:
                # Mark on the graph node
                node.is_god_module = True

                matched_cond_name = (
                    "condition_1 (loc+fan_out+fan_in)"
                    if matches_cond_1
                    else "condition_2 (loc+fan_out)"
                )

                threshold_reason = (
                    f"LOC: {node.loc} (threshold: > {self.loc_threshold_1}), "
                    f"fan-out: {node.fan_out} (threshold: > {self.fan_out_threshold_1}), "
                    f"fan-in: {node.fan_in} (threshold: > {self.fan_in_threshold_1})"
                    if matches_cond_1
                    else f"LOC: {node.loc} (threshold: > {self.loc_threshold_2}), "
                    f"fan-out: {node.fan_out} (threshold: > {self.fan_out_threshold_2})"
                )

                location = SourceLocation(
                    file_path=node.file_path,
                    line_start=1,
                    line_end=1,
                    col_start=0,
                    col_end=None,
                )

                snippet = f"// God Module Candidate: {node.module_name}\n// {threshold_reason}"
                evidence = {
                    "module": node.module_name,
                    "loc": node.loc,
                    "fan_in": node.fan_in,
                    "fan_out": node.fan_out,
                    "thresholds": {
                        "loc_threshold_1": self.loc_threshold_1,
                        "fan_out_threshold_1": self.fan_out_threshold_1,
                        "fan_in_threshold_1": self.fan_in_threshold_1,
                        "loc_threshold_2": self.loc_threshold_2,
                        "fan_out_threshold_2": self.fan_out_threshold_2,
                    },
                    "matched_condition": matched_cond_name,
                }
                findings.append(
                    self.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Module '{node.module_name}' satisfies God Module heuristic thresholds ({threshold_reason}). "
                            "This is a heuristic structural architecture smell based on LOC and coupling metrics, "
                            "indicating that this module serves as a disproportionately coupled hub."
                        ),
                        message=f"God Module structural smell candidate: '{node.module_name}'",
                        explanation=(
                            f"Module '{node.module_name}' satisfies God Module heuristic thresholds ({threshold_reason}). "
                            "This is a heuristic structural architecture smell based on LOC and coupling metrics, "
                            "indicating that this module serves as a disproportionately coupled hub."
                        ),
                        evidence=evidence,
                    )
                )

        return findings
