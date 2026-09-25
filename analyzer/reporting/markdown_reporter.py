"""Markdown report generator for PR/MR comment integration (Phase 14)."""

import html
from typing import Optional

from analyzer.models.comparison import ComparisonResult, FindingTransition
from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter

SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 1,
    FindingSeverity.HIGH: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 4,
    FindingSeverity.INFO: 5,
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def _escape_md_table(text: str) -> str:
    """Escape vertical bar pipe characters for Markdown table cells."""
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", " ")


class MarkdownReporter(BaseReporter):
    """Generates clean, GitHub/GitLab Pull Request friendly Markdown summaries."""

    def __init__(self, max_findings: int = 25):
        self.max_findings = max_findings

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a structured Markdown document."""
        lines = []
        repo = result.repository
        meta = result.metadata
        health = result.health
        sec = result.security_summary
        arch = result.architecture_summary

        lines.append("# 🛡️ CodeSentinel Static Analysis Report")
        lines.append("")

        # 1. Health Status Badges
        score = health.overall_score if health else 100.0
        grade = health.overall_grade if health else "A"
        sec_score = health.security_posture.score if health and health.security_posture else 100.0
        arch_score = health.architecture_health.score if health and health.architecture_health else 100.0

        lines.append(f"**Overall Health**: `{score:.1f}/100 (Grade {grade})` | "
                     f"**Security**: `{sec_score:.1f}/100` | "
                     f"**Architecture**: `{arch_score:.1f}/100`")
        lines.append("")

        # 2. Executive Summary Table
        lines.append("### 📊 Scan Summary")
        lines.append("| Metric | Value | Metric | Value |")
        lines.append("| :--- | :--- | :--- | :--- |")
        lines.append(f"| **Repository** | `{_escape_md_table(repo.name)}` | **Total Files** | `{repo.total_files:,}` |")
        dur_str = f"{meta.duration_seconds:.2f}s" if meta.duration_seconds is not None else "N/A"
        lines.append(f"| **Lines of Code** | `{repo.total_loc:,}` | **Scan Duration** | `{dur_str}` |")
        commit_str = repo.commit_hash[:10] if repo.commit_hash else "N/A"
        branch_str = repo.branch or "N/A"
        lines.append(f"| **Git Commit** | `{commit_str}` | **Git Branch** | `{_escape_md_table(branch_str)}` |")
        lines.append("")

        # 3. Severity Distribution
        lines.append("### 🚨 Finding Distribution")
        lines.append("| Severity | Count | Category | Count |")
        lines.append("| :--- | :--- | :--- | :--- |")
        lines.append(f"| 🔴 Critical | `{sec.critical}` | Security Total | `{sec.total}` |")
        lines.append(f"| 🟠 High | `{sec.high}` | Architecture Total | `{arch.total_findings}` |")
        lines.append(f"| 🟡 Medium | `{sec.medium}` | Circular Cycles | `{arch.circular_dependencies_count}` |")
        lines.append(f"| 🔵 Low | `{sec.low}` | God Modules | `{arch.god_modules_count}` |")
        lines.append(f"| ⚪ Info | `{sec.info}` | **Total Findings** | `{sec.total + arch.total_findings}` |")
        lines.append("")

        # 4. Top Findings Table
        all_findings = sorted(
            result.security_findings + result.architecture_findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 99),
                f.location.file_path,
                f.location.line_start or 0,
                f.rule_id,
            ),
        )

        lines.append(f"### 🔍 Detected Findings ({len(all_findings)})")
        if not all_findings:
            lines.append("✅ **Clean scan! Zero security vulnerabilities or architectural violations detected.**")
            lines.append("")
        else:
            lines.append("| Sev | Rule | Location | Description |")
            lines.append("| :---: | :--- | :--- | :--- |")
            displayed = all_findings[: self.max_findings]
            for f in displayed:
                sev_icon = SEVERITY_ICONS.get(f.severity.value, "⚪")
                loc_str = f"`{f.location.file_path}:{f.location.line_start or 1}`"
                desc_str = _escape_md_table(f.message or f.description)
                lines.append(f"| {sev_icon} | **{f.rule_id}** | {loc_str} | {desc_str} |")

            lines.append("")
            if len(all_findings) > self.max_findings:
                lines.append(f"> [!NOTE]\n> *Showing top {self.max_findings} of {len(all_findings)} findings. Run `codesentinel analyze` locally for complete details.*")
                lines.append("")

        # 5. Data-Flow & Taint Traces (Intra- and Inter-procedural)
        taint_findings = [
            f for f in all_findings
            if f.evidence and isinstance(f.evidence, dict) and f.evidence.get("flow_type") in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT")
        ]
        if taint_findings:
            lines.append("### 🧬 Data-Flow & Taint Traces")
            for idx, tf in enumerate(taint_findings[:5], start=1):
                summary = tf.evidence.get("path_summary", tf.message)
                is_inter = tf.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT"
                trace_type = "Cross-Function Taint" if is_inter else "Intraprocedural Taint"
                lines.append(f"<details><summary><b>Trace #{idx}: [{trace_type}] {tf.rule_id} in {tf.location.file_path}:{tf.location.line_start}</b></summary>")
                lines.append("")
                lines.append(f"```text\n{summary}\n```")
                lines.append("")
                if is_inter and "call_chain" in tf.evidence and isinstance(tf.evidence["call_chain"], list):
                    lines.append("**Call Chain Steps**:")
                    for c_idx, step in enumerate(tf.evidence["call_chain"], 1):
                        caller = step.get("caller_function", "?")
                        callee = step.get("callee_function", "?")
                        caller_f = step.get("caller_file", "?")
                        line = step.get("call_site_line", "?")
                        action = step.get("taint_action", "")
                        rec_type = step.get("receiver_type")
                        rec_conf = step.get("receiver_confidence")
                        ctx_id = step.get("context_id")
                        extra = []
                        if rec_type:
                            extra.append(f"Receiver: `{rec_type}` ({rec_conf or 'KNOWN'})")
                        alias_p = step.get("alias_path")
                        if alias_p:
                            extra.append(f"Alias: `{alias_p}`")
                        field_p = step.get("field_path")
                        if field_p:
                            extra.append(f"Field: `{field_p}`")
                        path_c = step.get("path_condition")
                        if path_c:
                            extra.append(f"Condition: `{path_c}`")
                        branch_t = step.get("branch_taken")
                        if branch_t:
                            extra.append(f"Branch: `{branch_t}`")
                        guard_p = step.get("guard_predicate")
                        if guard_p:
                            extra.append(f"Guard: `{guard_p}`")
                        if ctx_id and ctx_id != "ROOT":
                            extra.append(f"Context: `{ctx_id}`")
                        contract_st = step.get("contract_status")
                        if contract_st:
                            extra.append(f"Contract: `{contract_st}`")
                        contract_ef = step.get("contract_effect")
                        if contract_ef:
                            extra.append(f"Effect: `{contract_ef}`")
                        precond_k = step.get("precondition_kind")
                        if precond_k:
                            extra.append(f"Precondition: `{precond_k}`")
                        extra_str = f" [{', '.join(extra)}]" if extra else ""
                        lines.append(f"- Step {c_idx}: `{caller}()` → `{callee}()`{extra_str} at `{caller_f}:{line}` ({action})")
                    lines.append("")
                lines.append(f"**Remediation**: {tf.remediation}")
                lines.append("</details>")
                lines.append("")

        if result.call_graph_summary and "contracts" in result.call_graph_summary:
            contracts = result.call_graph_summary["contracts"]
            lines.append("### Interprocedural Contracts (Phase 19)")
            lines.append("| Metric | Value |")
            lines.append("| :--- | :--- |")
            lines.append(f"| Contracts Generated | {contracts.get('contracts_generated', 0)} |")
            lines.append(f"| Preconditions Verified | {contracts.get('preconditions_verified', 0)} |")
            lines.append(f"| Postconditions Propagated | {contracts.get('postconditions_propagated', 0)} |")
            lines.append(f"| Multi-Hop Guards Resolved | {contracts.get('multi_hop_guards_resolved', 0)} |")
            if contracts.get("contracts_widened"):
                lines.append(f"| Contracts Widened | {contracts.get('contracts_widened', 0)} |")
            if contracts.get("recursive_sccs_resolved"):
                lines.append(f"| Recursive SCC Cycles | {contracts.get('recursive_sccs_resolved', 0)} |")
            lines.append("")

        lines.append("---")
        lines.append("*Generated deterministically by CodeSentinel Static Analysis Engine.*")
        return "\n".join(lines)

    def render_comparison(self, comparison: ComparisonResult) -> str:
        """Render a differential ComparisonResult into PR review Markdown."""
        lines = []
        s = comparison.summary
        hd = comparison.health_delta

        lines.append("# ⚖️ CodeSentinel Differential Regression Report")
        lines.append("")

        # 1. Summary Badges
        lines.append(f"**New Regressions**: `{s.new_count}` | "
                     f"**Resolved (Fixed)**: `{s.resolved_count}` | "
                     f"**Unchanged**: `{s.unchanged_count}` | "
                     f"**Modified**: `{s.modified_count}`")
        lines.append("")

        # 2. Health Impact Table
        if hd:
            delta_symbol = "+" if hd.score_delta >= 0 else ""
            lines.append("### 📈 Health Impact")
            lines.append("| Metric | Baseline | Current | Delta |")
            lines.append("| :--- | :---: | :---: | :---: |")
            lines.append(f"| Overall Health | `{hd.baseline_score or 0.0:.1f}` | `{hd.current_score or 0.0:.1f}` | `{delta_symbol}{hd.score_delta:.1f} pts` |")
            lines.append(f"| Health Grade | `{hd.baseline_grade or 'N/A'}` | `{hd.current_grade or 'N/A'}` | `{'Grade Changed' if hd.grade_changed else 'Unchanged'}` |")
            lines.append("")

        # 3. New Findings Table
        new_findings = [df for df in comparison.findings if df.transition == FindingTransition.NEW]
        lines.append(f"### 🔴 Newly Introduced Findings ({len(new_findings)})")
        if not new_findings:
            lines.append("✅ **No new regressions introduced in this change.**")
            lines.append("")
        else:
            lines.append("| Sev | Rule | Location | Description |")
            lines.append("| :---: | :--- | :--- | :--- |")
            for df in new_findings[: self.max_findings]:
                f = df.finding
                sev_icon = SEVERITY_ICONS.get(f.severity.value, "⚪")
                loc_str = f"`{f.location.file_path}:{f.location.line_start or 1}`"
                lines.append(f"| {sev_icon} | **{f.rule_id}** | {loc_str} | {_escape_md_table(f.message)} |")
            lines.append("")

        # 4. Resolved Findings Table
        resolved_findings = [df for df in comparison.findings if df.transition == FindingTransition.RESOLVED]
        lines.append(f"### 🟢 Resolved Findings ({len(resolved_findings)})")
        if resolved_findings:
            lines.append("| Rule | Location | Previously Flagged |")
            lines.append("| :--- | :--- | :--- |")
            for df in resolved_findings[:15]:
                f = df.finding
                loc_str = f"`{f.location.file_path}:{f.location.line_start or 1}`"
                lines.append(f"| **{f.rule_id}** | {loc_str} | {_escape_md_table(f.message)} |")
            lines.append("")

        lines.append("---")
        lines.append("*Generated deterministically by CodeSentinel Baseline Comparator.*")
        return "\n".join(lines)
