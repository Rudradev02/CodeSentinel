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
            # Phase 6: Enriched dependency category counts
            lines.append(
                f"    Dependencies: Local: {m.local_dependencies_count} | "
                f"StdLib: {m.stdlib_dependencies_count} | "
                f"External: {m.external_dependencies_count} | "
                f"Unresolved: {m.unresolved_dependencies_count}"
            )
            lines.append(
                f"    Connected Components: {m.connected_components_count} weakly | "
                f"{m.strongly_connected_components_count} strongly"
            )

        if result.call_graph_summary:
            cg = result.call_graph_summary
            lines.append("  CALL GRAPH INTELLIGENCE:")
            lines.append(
                f"    Functions: {cg.get('total_functions', 0)} | Call Edges: {cg.get('total_call_edges', 0)} | "
                f"Resolved: {cg.get('resolved_local', 0)} local, {cg.get('resolved_import', 0)} import | "
                f"Resolution Rate: {cg.get('resolution_rate', 0.0):.1%}"
            )
            lines.append(
                f"    Summaries: {cg.get('summarized_functions', 0)} | "
                f"Cross-Function Findings: {cg.get('interprocedural_findings_count', 0)} | "
                f"Max Depth: {cg.get('max_call_depth_reached', 0)}"
            )
            if "alias_analysis" in cg and cg["alias_analysis"]:
                aa = cg["alias_analysis"]
                lines.append(
                    f"    Alias & Points-To: {aa.get('abstract_objects_count', 0)} objects | "
                    f"{aa.get('alias_bindings_count', 0)} bindings | "
                    f"{aa.get('field_edges_count', 0)} fields | "
                    f"{aa.get('ambiguous_points_to_count', 0)} ambiguous | "
                    f"{aa.get('truncated_points_to_count', 0)} widened"
                )
            if "path_sensitivity" in cg and cg["path_sensitivity"]:
                ps = cg["path_sensitivity"]
                lines.append(
                    f"    Path & Guard Analysis: {ps.get('cfg_blocks_analyzed', 0)} blocks | "
                    f"{ps.get('guards_evaluated', 0)} guards | "
                    f"{ps.get('guarded_paths_pruned', 0)} paths pruned | "
                    f"{ps.get('paths_truncated_budget', 0)} budget truncations"
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

        # Phase 6: Dependency Resolution Diagnostics
        if hasattr(result, 'dependency_diagnostics') and result.dependency_diagnostics:
            lines.append(divider)
            lines.append(f"  DEPENDENCY RESOLUTION DIAGNOSTICS ({len(result.dependency_diagnostics)})")
            lines.append(divider)
            # Group by diagnostic_type for conciseness
            by_type: dict[str, list] = {}
            for diag in result.dependency_diagnostics:
                by_type.setdefault(diag.diagnostic_type, []).append(diag)
            for dtype, diags in sorted(by_type.items()):
                lines.append(f"  [{dtype}] ({len(diags)} occurrence(s)):")
                for d in diags[:10]:  # Show at most 10 per type
                    loc = d.file_path
                    if d.line_number:
                        loc += f":{d.line_number}"
                    lines.append(f"    - {loc}: {d.message}")
                if len(diags) > 10:
                    lines.append(f"    ... and {len(diags) - 10} more")

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

        # Phase 7: Codebase Health Scoring
        if result.health:
            h = result.health
            lines.append(divider)
            lines.append(f"  CODEBASE HEALTH GRADE: {h.overall_grade} ({h.overall_score:.2f} / 100.00)")
            lines.append(divider)
            lines.append(f"    Architecture Health : {h.architecture_health.grade} ({h.architecture_health.score:.2f} / 100.00)")
            lines.append(f"    Security Posture    : {h.security_posture.grade} ({h.security_posture.score:.2f} / 100.00)")
            lines.append(f"    Summary: {h.summary}")
            all_deductions = sorted(
                h.architecture_health.deductions + h.security_posture.deductions,
                key=lambda d: d.points_deducted,
                reverse=True,
            )
            if all_deductions:
                lines.append("    Top Risk Deductions:")
                for d in all_deductions[:5]:
                    lines.append(f"      - -{d.points_deducted:.1f} pts [{d.rule_id}] {d.reason} ({d.item_count} instance(s))")

        # Phase 7: Component Graph Summary
        if result.graph and result.graph.component_graph:
            cg = result.graph.component_graph
            lines.append(sub_divider)
            lines.append(f"  COMPONENT GRAPH ({len(cg.nodes)} components, {len(cg.edges)} edges):")
            for node in sorted(cg.nodes, key=lambda n: n.id)[:10]:
                tier_str = f" [{node.layer}]" if node.layer else ""
                lines.append(
                    f"    - {node.id}{tier_str}: {len(node.files)} files | "
                    f"Ca={node.metrics.afferent_coupling} | Ce={node.metrics.efferent_coupling} | "
                    f"I={node.metrics.instability:.2f}"
                )
        # Phase 16: Type & Context Precision Summary
        if result.call_graph_summary:
            cgs = result.call_graph_summary
            tr = cgs.get("type_resolution")
            cs = cgs.get("context_sensitivity")
            if tr or cs:
                lines.append(sub_divider)
                lines.append("  TYPE & CONTEXT PRECISION (PHASE 16):")
                if tr:
                    lines.append(f"    Types Inferred      : {tr.get('types_inferred', 0)}")
                    lines.append(f"    Type-Aware Edges    : {tr.get('type_aware_edges', 0)}")
                    lines.append(f"    Ambiguous Receivers : {tr.get('ambiguous_receivers', 0)}")
                if cs:
                    lines.append(f"    Active Contexts     : {cs.get('total_contexts', 0)}")
                    lines.append(f"    Max Context Depth   : {cs.get('max_depth_reached', 0)}")
                    if cs.get("contexts_truncated"):
                        lines.append(f"    Contexts Truncated  : {cs.get('contexts_truncated', 0)}")
            ps = cgs.get("path_sensitivity")
            if ps:
                lines.append(sub_divider)
                lines.append("  PATH SENSITIVITY & GUARDS (PHASE 18):")
                lines.append(f"    CFG Blocks Analyzed : {ps.get('cfg_blocks_analyzed', 0)}")
                lines.append(f"    Guards Evaluated    : {ps.get('guards_evaluated', 0)}")
                lines.append(f"    Guarded Paths Pruned: {ps.get('guarded_paths_pruned', 0)}")
                if ps.get("paths_truncated_budget"):
                    lines.append(f"    Budget Truncations  : {ps.get('paths_truncated_budget', 0)}")
            contracts = cgs.get("contracts")
            if contracts:
                lines.append(sub_divider)
                lines.append("  INTERPROCEDURAL CONTRACTS (PHASE 19):")
                lines.append(f"    Contracts Generated : {contracts.get('contracts_generated', 0)}")
                lines.append(f"    Preconditions Proven: {contracts.get('preconditions_verified', 0)}")
                lines.append(f"    Postconditions Bound: {contracts.get('postconditions_propagated', 0)}")
                lines.append(f"    Multi-Hop Resolved  : {contracts.get('multi_hop_guards_resolved', 0)}")
                if contracts.get("contracts_widened"):
                    lines.append(f"    Contracts Widened   : {contracts.get('contracts_widened', 0)}")
                if contracts.get("recursive_sccs_resolved"):
                    lines.append(f"    Recursive SCC Cycles: {contracts.get('recursive_sccs_resolved', 0)}")

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
            if f.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT":
                out.append("      Interprocedural Taint Flow:")
                if "path_summary" in f.evidence:
                    out.append(f"        Path       : {f.evidence['path_summary']}")
                if "call_chain" in f.evidence and isinstance(f.evidence["call_chain"], list):
                    out.append("        Call Chain :")
                    for step_idx, step in enumerate(f.evidence["call_chain"], 1):
                        if isinstance(step, dict):
                            caller = step.get("caller_function", "?")
                            callee = step.get("callee_function", "?")
                            caller_file = step.get("caller_file", "?")
                            line = step.get("call_site_line", "?")
                            action = step.get("taint_action", "")
                            rec_type = step.get("receiver_type")
                            conf = step.get("receiver_confidence")
                            ctx_id = step.get("context_id")
                            extra = []
                            if rec_type:
                                conf_str = f" ({conf})" if conf else ""
                                extra.append(f"Receiver: {rec_type}{conf_str}")
                            alias_p = step.get("alias_path")
                            if alias_p:
                                extra.append(f"Alias: {alias_p}")
                            field_p = step.get("field_path")
                            if field_p:
                                extra.append(f"Field: {field_p}")
                            path_c = step.get("path_condition")
                            if path_c:
                                extra.append(f"Condition: {path_c}")
                            branch_t = step.get("branch_taken")
                            if branch_t:
                                extra.append(f"Branch: {branch_t}")
                            guard_p = step.get("guard_predicate")
                            if guard_p:
                                extra.append(f"Guard: {guard_p}")
                            if ctx_id and ctx_id != "ROOT":
                                extra.append(f"Context: {ctx_id}")
                            extra_str = f" [{' | '.join(extra)}]" if extra else ""
                            out.append(f"          [{step_idx}] {caller}() -> {callee}(){extra_str} at {caller_file}:{line} ({action})")
                if "files_involved" in f.evidence:
                    out.append(f"        Files      : {', '.join(f.evidence['files_involved'])}")
            else:
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
