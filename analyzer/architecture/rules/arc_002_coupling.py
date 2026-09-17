"""ARC-002: Excessive Fan-Out / Coupling Anti-Pattern."""

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph

DEFAULT_FAN_OUT_THRESHOLD = 10


class RuleArc002(BaseArchitectureRule):
    """ARC-002: Excessive Fan-Out / Coupling."""

    rule_id = "ARC-002"
    name = "Excessive Fan-Out Coupling"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.HIGH
    description = (
        "Detected module with excessive efferent coupling (fan-out). "
        "A module that directly depends on an unusually large number of other modules "
        "is fragile because changes in any upstream dependency can trigger ripple effects."
    )
    rationale = (
        "High efferent coupling indicates that a module has too many external responsibilities, "
        "making it fragile and sensitive to upstream changes across the system."
    )
    remediation = (
        "Reduce fan-out by applying the Facade pattern, aggregating dependencies behind "
        "cohesive service abstractions, or decomposing the module into smaller single-responsibility units."
    )

    def __init__(self, threshold: int = DEFAULT_FAN_OUT_THRESHOLD):
        self.threshold = threshold

    def analyze(self, graph: ArchitectureGraph) -> list[Finding]:
        findings: list[Finding] = []

        for node in graph.nodes:
            # Only evaluate local repository files
            if node.is_external:
                continue

            if node.fan_out > self.threshold:
                location = SourceLocation(
                    file_path=node.file_path,
                    line_start=1,
                    line_end=1,
                    col_start=0,
                    col_end=None,
                )

                snippet = f"// Module: {node.module_name} (fan_out: {node.fan_out}, threshold: {self.threshold})"
                evidence = {
                    "module": node.module_name,
                    "fan_out": node.fan_out,
                    "threshold": self.threshold,
                }
                findings.append(
                    self.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Module '{node.module_name}' exhibits high efferent coupling with {node.fan_out} "
                            f"outgoing dependencies (threshold: > {self.threshold}). This structural metric indicates "
                            "that this module is sensitive to modifications across many parts of the codebase."
                        ),
                        message=f"High efferent coupling on module '{node.module_name}' (fan-out: {node.fan_out})",
                        explanation=(
                            f"Module '{node.module_name}' exhibits high efferent coupling with {node.fan_out} "
                            f"outgoing dependencies (threshold: > {self.threshold}). This structural metric indicates "
                            "that this module is sensitive to modifications across many parts of the codebase."
                        ),
                        evidence=evidence,
                    )
                )

        return findings
