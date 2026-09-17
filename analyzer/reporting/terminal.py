"""Human-readable terminal reporter for CodeSentinel analysis results."""

from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter


class TerminalReporter(BaseReporter):
    """Formats AnalysisResult into a clear, structured terminal report."""

    def __init__(self, use_color: bool = False):
        self.use_color = use_color

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a human-readable text report."""
        lines: list[str] = []
        divider = "=" * 78
        sub_divider = "-" * 78

        # Header
        lines.append(divider)
        lines.append("  CODESENTINEL REPOSITORY STATIC ANALYSIS REPORT")
        lines.append(divider)
        lines.append(f"  Target Repository : {result.repository.name} ({result.repository.local_path})")
        lines.append(f"  Engine Version    : {result.metadata.engine_version}")
        duration_str = f"{result.metadata.duration_seconds:.2f}s" if result.metadata.duration_seconds is not None else "N/A"
        lines.append(f"  Analysis Duration : {duration_str}")
        lines.append(f"  Files Analyzed    : {result.repository.total_files} files ({result.repository.total_loc:,} lines of code)")

        # Languages
        if result.repository.detected_languages:
            langs = ", ".join(
                f"{lang} ({count})"
                for lang, count in sorted(result.repository.detected_languages.items())
            )
            lines.append(f"  Languages         : {langs}")
        else:
            lines.append("  Languages         : None detected")

        # Frameworks
        if result.repository.detected_frameworks:
            lines.append(f"  Frameworks        : {', '.join(sorted(result.repository.detected_frameworks))}")
        else:
            lines.append("  Frameworks        : None detected")

        lines.append(sub_divider)

        # Summaries
        sec = result.security_summary
        lines.append("  SECURITY FINDINGS SUMMARY:")
        lines.append(
            f"    Total: {sec.total} | Critical: {sec.critical} | High: {sec.high} | "
            f"Medium: {sec.medium} | Low: {sec.low} | Info: {sec.info}"
        )
        lines.append(
            f"    Evidence Types: {sec.deterministic_count} Deterministic, {sec.heuristic_count} Heuristic"
        )

        arch = result.architecture_summary
        lines.append("  ARCHITECTURE SUMMARY:")
        lines.append(
            f"    Modules: {arch.total_modules} | Circular Cycles: {arch.circular_dependencies_count} | "
            f"God Modules: {arch.god_modules_count} | Total Smells: {arch.total_findings}"
        )

        if result.graph and result.graph.metrics:
            m = result.graph.metrics
            lines.append(
                f"    Graph Density: {m.density:.4f} | Avg Fan-In: {m.average_fan_in} | "
                f"Avg Fan-Out: {m.average_fan_out} | Max Fan-Out: {m.max_fan_out}"
            )

        # Detailed Security Findings
        if result.security_findings:
            lines.append(divider)
            lines.append("  SECURITY FINDINGS DETAILS")
            lines.append(divider)
            for i, f in enumerate(result.security_findings, 1):
                lines.extend(self._format_finding(i, f, "SECURITY"))

        # Detailed Architecture Findings
        if result.architecture_findings:
            lines.append(divider)
            lines.append("  ARCHITECTURE SMELL DETAILS")
            lines.append(divider)
            for i, f in enumerate(result.architecture_findings, 1):
                lines.extend(self._format_finding(i, f, "ARCHITECTURE"))

        # Circular Dependencies breakdown if any
        if result.graph and result.graph.circular_dependencies:
            lines.append(divider)
            lines.append("  CIRCULAR DEPENDENCY CYCLES")
            lines.append(divider)
            for i, cycle in enumerate(result.graph.circular_dependencies, 1):
                cycle_str = " -> ".join(cycle.modules)
                lines.append(f"  Cycle #{i} ({cycle.length} modules):")
                lines.append(f"    {cycle_str}")

        # Parsing Errors / Non-fatal warnings
        if result.parsing_errors:
            lines.append(divider)
            lines.append(f"  PARSING WARNINGS / ERRORS ({len(result.parsing_errors)})")
            lines.append(divider)
            for pe in result.parsing_errors:
                loc = f"{pe.file_path}"
                if pe.line_number:
                    loc += f":{pe.line_number}"
                if pe.column_number is not None:
                    loc += f":{pe.column_number}"
                lines.append(f"  - [{loc}] {pe.error_message}")

        # Clean Scan Notice
        total_findings = len(result.security_findings) + len(result.architecture_findings)
        if total_findings == 0:
            lines.append(divider)
            lines.append("  RESULT: Clean audit - zero security or architectural findings.")
            lines.append(divider)
        else:
            lines.append(divider)
            lines.append(f"  RESULT: Completed with {total_findings} total finding(s).")
            lines.append(divider)

        return "\n".join(lines)

    def _format_finding(self, index: int, f: Finding, category_label: str) -> list[str]:
        out: list[str] = []
        loc = f"{f.location.file_path}:{f.location.line_start}"
        if f.location.col_start is not None:
            loc += f":{f.location.col_start}"

        out.append(f"  [{index}] [{f.severity.value}] {f.rule_id}: {f.rule_name}")
        out.append(f"      Category   : {category_label} | Evidence: {f.evidence_type.value} | Confidence: {f.confidence.value}")
        out.append(f"      Location   : {loc}")
        if f.message and f.message != f.rule_name:
            out.append(f"      Message    : {f.message}")
        if f.explanation:
            out.append(f"      Explanation: {f.explanation}")
        elif f.description:
            out.append(f"      Description: {f.description}")

        if f.evidence:
            out.append("      Evidence   :")
            for k, v in sorted(f.evidence.items()):
                if isinstance(v, dict):
                    out.append(f"        - {k}:")
                    for sub_k, sub_v in sorted(v.items()):
                        out.append(f"            {sub_k}: {sub_v}")
                elif isinstance(v, list):
                    out.append(f"        - {k}: {', '.join(str(item) for item in v)}")
                else:
                    out.append(f"        - {k}: {v}")

        # Indent code snippet
        out.append("      Snippet    :")
        for line in f.code_snippet.splitlines():
            out.append(f"        | {line}")

        out.append(f"      Remediation: {f.remediation}")
        out.append("")
        return out
