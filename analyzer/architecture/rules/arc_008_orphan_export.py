"""ARC-008: Potentially Orphaned Export Rule.

Flags public module exports that have no observable internal callers or imports within the repository.
"""

from typing import Optional
from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.architecture.orphan_exports import OrphanExportAnalyzer
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph
from analyzer.models.parse import ParsedFile


class RuleArc008(BaseArchitectureRule):
    """ARC-008: Potentially Orphaned Export."""

    rule_id = "ARC-008"
    name = "Potentially Orphaned Export"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.LOW
    confidence = FindingConfidence.MEDIUM
    description = (
        "Detected public exported symbol that has no observable internal callers or imports "
        "within the repository. Dead or unused exports inflate public API surface and maintenance overhead."
    )
    rationale = (
        "Public symbols without internal callers indicate either dead/obsolete code, uncompleted features, "
        "or orphaned abstractions that can safely be removed or demoted to internal private scope."
    )
    remediation = (
        "If the symbol is no longer needed, remove it or deprecate it. If it is only used internally "
        "within its declaring module, remove the export statement. If this repository is a published "
        "public library intended for external consumers, consider marking entry points or disabling ARC-008."
    )

    def __init__(self, orphan_analyzer: Optional[OrphanExportAnalyzer] = None):
        self.orphan_analyzer = orphan_analyzer or OrphanExportAnalyzer()

    def analyze(self, graph: ArchitectureGraph, parsed_files: Optional[list[ParsedFile]] = None, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        if not parsed_files:
            return findings

        orphan_records = self.orphan_analyzer.find_orphan_exports(parsed_files)

        for rec in orphan_records:
            location = SourceLocation(
                file_path=rec.file_path,
                line_start=rec.line_number or 1,
                line_end=rec.line_number or 1,
                col_start=0,
                col_end=None,
            )

            snippet = f"// Potentially orphaned export:\nexport {rec.symbol_name}"
            evidence = {
                "symbol_name": rec.symbol_name,
                "symbol": rec.symbol_name,
                "is_default": rec.is_default,
                "file_path": rec.file_path,
                "scope": "INTERNAL_REPOSITORY_CHECK",
            }

            msg = f"Potentially orphaned export '{rec.symbol_name}'"
            expl = (
                f"Exported symbol '{rec.symbol_name}' in '{rec.file_path}' has no observable internal "
                f"callers or import references within the repository. If not part of a public external API, "
                f"it may represent dead code or unneeded public surface."
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

        findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line_start,
                f.location.col_start or 0,
                f.rule_id,
            )
        )
        return findings
