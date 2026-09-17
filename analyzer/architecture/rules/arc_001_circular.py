"""ARC-001: Circular Dependency Anti-Pattern."""

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class RuleArc001(BaseArchitectureRule):
    """ARC-001: Circular Dependency."""

    rule_id = "ARC-001"
    name = "Circular Dependency"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    description = (
        "Detected circular import dependency cycle between two or more modules. "
        "Mutual dependency cycles prevent modular decoupling, complicate testing, and "
        "can lead to unexpected runtime initialization failures and memory leaks."
    )
    rationale = (
        "Mutual dependency cycles couple components bidirectionally, preventing clean architectural layering, "
        "complicating unit testing, and causing runtime import or initialization failures."
    )
    remediation = (
        "Break the cycle by extracting shared types/interfaces to a common leaf module, "
        "reorganizing domain boundaries, or using dependency injection."
    )

    def analyze(self, graph: ArchitectureGraph) -> list[Finding]:
        findings: list[Finding] = []

        # Dedup cycles by canonical sorted representation
        seen_cycles: set[str] = set()

        for cycle in graph.circular_dependencies:
            if not cycle.modules or len(cycle.modules) < 2:
                continue

            cycle_key = "->".join(sorted(cycle.modules))
            if cycle_key in seen_cycles:
                continue
            seen_cycles.add(cycle_key)

            # The primary location is the first participating module
            first_module = cycle.modules[0]
            cycle_path = " -> ".join(cycle.modules) + f" -> {cycle.modules[0]}"

            # Attempt to find the participating edge line number if recorded
            line_start = 1
            for edge in graph.edges:
                if edge.source == cycle.modules[0] and edge.target == cycle.modules[1]:
                    if edge.line_number:
                        line_start = edge.line_number
                        break

            location = SourceLocation(
                file_path=first_module,
                line_start=line_start,
                line_end=line_start,
                col_start=0,
                col_end=None,
            )

            snippet = f"// Circular dependency cycle:\n{cycle_path}"
            evidence = {
                "cycle": cycle.modules,
                "cycle_length": len(cycle.modules),
                "cycle_path": cycle_path,
            }
            findings.append(
                self.create_finding(
                    location=location,
                    code_snippet=snippet,
                    custom_description=(
                        f"Circular dependency cycle detected across {len(cycle.modules)} modules: "
                        f"[{cycle_path}]. Cyclic dependencies couple components tightly and hinder reusability."
                    ),
                    message=f"Circular dependency cycle ({len(cycle.modules)} modules)",
                    explanation=(
                        f"Circular dependency cycle detected across {len(cycle.modules)} modules: "
                        f"[{cycle_path}]. Cyclic dependencies couple components tightly and hinder reusability."
                    ),
                    evidence=evidence,
                )
            )

        return findings
