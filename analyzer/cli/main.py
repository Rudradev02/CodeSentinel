import argparse
import json
from pathlib import Path
import sys
from typing import Optional

from analyzer.comparison.diff import BaselineComparator
from analyzer.config.file_loader import load_repo_config
from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.comparison import ComparisonResult, FindingTransition
from analyzer.models.findings import FindingCategory, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.gitlab_reporter import GitlabReporter
from analyzer.reporting.html_reporter import HtmlReporter
from analyzer.reporting.json_reporter import JsonReporter
from analyzer.reporting.junit_reporter import JunitReporter
from analyzer.reporting.markdown_reporter import MarkdownReporter
from analyzer.reporting.sarif import SarifReporter
from analyzer.reporting.terminal import TerminalReporter, render_incremental_stats_table
from analyzer.incremental.cache import AnalysisCache, DiskAnalysisCache, NullAnalysisCache
from analyzer.incremental.equivalence import EquivalenceChecker
from analyzer.rules.registry import RuleRegistry

SEVERITY_RANKS: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.HIGH: 4,
    FindingSeverity.CRITICAL: 5,
}


def _split_comma_rules(rule_args: Optional[list[str]]) -> list[str]:
    """Parse list of rule strings that may contain comma-separated IDs."""
    if not rule_args:
        return []
    result: list[str] = []
    for arg in rule_args:
        for part in arg.split(","):
            cleaned = part.strip()
            if cleaned:
                result.append(cleaned)
    return result


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser for CodeSentinel."""
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="CodeSentinel: Deterministic Developer Security & Architecture Static Analysis Engine",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="codesentinel-analyzer 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a local repository for security vulnerabilities and architectural smells",
    )
    analyze_parser.add_argument(
        "path",
        help="Target repository directory path to analyze",
    )
    analyze_parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        default=None,
        help="Explicit path to repository configuration file (.codesentinel.yml or .codesentinel.json)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html", "markdown", "junit", "gitlab"],
        default=None,
        help="Output report format (default: terminal, or as configured in repo config)",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        default=None,
        help="Optional file path to write report to (default: stdout)",
    )
    analyze_parser.add_argument(
        "--baseline",
        dest="baseline_path",
        default=None,
        help="Path to baseline report JSON file for differential comparison",
    )
    analyze_parser.add_argument(
        "--fail-on-regression",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit code 2 only if newly introduced findings meet or exceed requested severity",
    )
    analyze_parser.add_argument(
        "--enable-rule",
        action="append",
        dest="enabled_rules",
        default=None,
        help="Explicitly enable specific rule ID(s). Can be repeated or comma-separated.",
    )
    analyze_parser.add_argument(
        "--disable-rule",
        action="append",
        dest="disabled_rules",
        default=None,
        help="Explicitly disable specific rule ID(s). Can be repeated or comma-separated.",
    )
    analyze_parser.add_argument(
        "--god-module-loc",
        type=int,
        default=None,
        help="Override primary lines-of-code threshold for ARC-003 God Module detection (default: 500)",
    )
    analyze_parser.add_argument(
        "--max-component-depth",
        type=int,
        default=None,
        help="Override maximum directory depth for component aggregation (default: 2)",
    )
    analyze_parser.add_argument(
        "--centrality-threshold",
        type=float,
        default=None,
        help="Override betweenness centrality threshold for ARC-009 bottleneck detection (default: 0.35)",
    )
    analyze_parser.add_argument(
        "--max-taint-depth",
        type=int,
        default=None,
        help="Override maximum propagation depth for intraprocedural taint analysis (default: 25)",
    )
    analyze_parser.add_argument(
        "--max-call-depth",
        type=int,
        default=None,
        help="Override maximum call depth for interprocedural taint analysis (default: 5)",
    )
    analyze_parser.add_argument(
        "--disable-interprocedural",
        action="store_true",
        default=False,
        help="Disable interprocedural call graph construction and cross-function taint analysis",
    )
    analyze_parser.add_argument(
        "--disable-type-inference",
        action="store_true",
        default=False,
        help="Disable conservative receiver type inference (Phase 16)",
    )
    analyze_parser.add_argument(
        "--disable-context-sensitivity",
        action="store_true",
        default=False,
        help="Disable context-sensitive call string tracking (Phase 16)",
    )
    analyze_parser.add_argument(
        "--max-k",
        type=int,
        default=None,
        help="Override maximum call-string context suffix length (default: 2, max: 2)",
    )
    analyze_parser.add_argument(
        "--max-contexts-per-function",
        type=int,
        default=None,
        help="Override maximum contexts evaluated per function before widening (default: 8)",
    )
    analyze_parser.add_argument(
        "--max-summary-iterations",
        type=int,
        default=None,
        help="Override maximum fixed-point summary iterations for recursive SCCs (default: 5)",
    )
    analyze_parser.add_argument(
        "--disable-alias-analysis",
        action="store_true",
        default=False,
        help="Disable alias and points-to analysis (falls back cleanly to Phase 16)",
    )
    analyze_parser.add_argument(
        "--disable-field-sensitivity",
        action="store_true",
        default=False,
        help="Disable field-sensitive state tracking (Phase 17)",
    )
    analyze_parser.add_argument(
        "--max-points-to-candidates",
        type=int,
        default=None,
        help="Override maximum points-to targets before widening (default: 4)",
    )
    analyze_parser.add_argument(
        "--max-fields-per-object",
        type=int,
        default=None,
        help="Override maximum fields tracked per abstract object (default: 16)",
    )
    analyze_parser.add_argument(
        "--max-objects-per-function",
        type=int,
        default=None,
        help="Override maximum abstract objects instantiated per function (default: 32)",
    )
    analyze_parser.add_argument(
        "--max-alias-iterations",
        type=int,
        default=None,
        help="Override maximum intraprocedural alias fixed-point iterations (default: 5)",
    )
    # Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis
    analyze_parser.add_argument(
        "--disable-path-sensitivity",
        action="store_true",
        default=False,
        help="Disable path-sensitive analysis (falls back cleanly to Phase 17)",
    )
    analyze_parser.add_argument(
        "--disable-guard-analysis",
        action="store_true",
        default=False,
        help="Disable guard and refinement reasoning (Phase 18)",
    )
    analyze_parser.add_argument(
        "--max-active-paths",
        type=int,
        default=None,
        help="Override maximum active exploration paths per function before widening (default: 8)",
    )
    analyze_parser.add_argument(
        "--max-total-path-states",
        type=int,
        default=None,
        help="Override maximum total path states explored per function (default: 128)",
    )
    analyze_parser.add_argument(
        "--max-branch-depth",
        type=int,
        default=None,
        help="Override maximum branch depth before path truncation (default: 6)",
    )
    analyze_parser.add_argument(
        "--max-conditions-per-path",
        type=int,
        default=None,
        help="Override maximum guard conditions accumulated per path (default: 16)",
    )
    analyze_parser.add_argument(
        "--max-cfg-blocks",
        type=int,
        default=None,
        help="Override maximum CFG basic blocks constructed per function (default: 64)",
    )
    # Phase 19: Path-Sensitive Interprocedural Contracts & Function Summaries
    analyze_parser.add_argument(
        "--disable-interprocedural-contracts",
        action="store_true",
        default=False,
        help="Disable interprocedural contracts (falls back cleanly to Phase 18)",
    )
    analyze_parser.add_argument(
        "--max-cached-contracts",
        type=int,
        default=None,
        help="Override maximum cached contract summaries before deterministic eviction (default: 2000)",
    )
    analyze_parser.add_argument(
        "--max-effects-per-summary",
        type=int,
        default=None,
        help="Override maximum conditional effects extracted per function summary (default: 16)",
    )
    analyze_parser.add_argument(
        "--max-field-effect-depth",
        type=int,
        default=None,
        help="Override maximum field traversal depth for contract postconditions (default: 3)",
    )
    # Phase 20: Project-Wide Contract Composition & Security Boundary Reasoning
    analyze_parser.add_argument(
        "--disable-contract-composition",
        action="store_true",
        default=False,
        help="Disable contract composition and security boundary reasoning (Phase 20)",
    )
    analyze_parser.add_argument(
        "--max-contract-composition-depth",
        type=int,
        default=None,
        help="Override maximum call chain depth for cross-function contract composition (default: 5)",
    )
    analyze_parser.add_argument(
        "--max-exception-contracts",
        type=int,
        default=None,
        help="Override maximum exceptional postcondition contracts per function (default: 16)",
    )
    analyze_parser.add_argument(
        "--max-contract-conflicts",
        type=int,
        default=None,
        help="Override maximum conflicting fact pairs recorded before widening (default: 32)",
    )
    analyze_parser.add_argument(
        "--max-container-fields",
        type=int,
        default=None,
        help="Override maximum dictionary/container fields tracked for contract refinements (default: 16)",
    )
    analyze_parser.add_argument(
        "--max-project-contract-nodes",
        type=int,
        default=None,
        help="Override maximum nodes retained in the project contract graph (default: 1000)",
    )
    analyze_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with code 2 if any finding has severity equal to or higher than requested severity",
    )
    analyze_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "critical", "high", "medium", "low", "info"],
        default=None,
        help="Filter reported findings to only those with severity equal to or higher than specified (CRITICAL > HIGH > MEDIUM > LOW > INFO)",
    )
    analyze_parser.add_argument(
        "--category",
        choices=["SECURITY", "ARCHITECTURE", "security", "architecture"],
        default=None,
        help="Filter reported findings by category (SECURITY or ARCHITECTURE)",
    )
    analyze_parser.add_argument(
        "--rule",
        action="append",
        dest="rule_filters",
        default=None,
        help="Filter reported findings to specific rule ID(s) (e.g. ARC-001, SEC-PY-001). Can be repeated or comma-separated.",
    )
    analyze_parser.add_argument(
        "--save",
        action="store_true",
        default=False,
        help="Optional: persist completed analysis snapshot to CodeSentinel backend API",
    )
    analyze_parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="Backend API base URL for optional persistence synchronization (default: http://localhost:8000)",
    )
    # Phase 21: Incremental Analysis & Caching
    analyze_parser.add_argument(
        "--incremental",
        action="store_true",
        default=False,
        help="Opt into incremental analysis mode (default: disabled)",
    )
    analyze_parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Bypass cache reads and writes for the current run",
    )
    analyze_parser.add_argument(
        "--cache-dir",
        default=None,
        help="Override custom cache directory (default: <repo_root>/.codesentinel_cache)",
    )
    analyze_parser.add_argument(
        "--clear-cache",
        action="store_true",
        default=False,
        help="Purge cached analysis artifacts for this repository and exit",
    )
    analyze_parser.add_argument(
        "--cache-stats",
        action="store_true",
        default=False,
        help="Display detailed cache telemetry and storage metrics after analysis",
    )
    analyze_parser.add_argument(
        "--verify-equivalence",
        action="store_true",
        default=False,
        help="Execute full analysis in parallel and verify equivalence (test/debug mode)",
    )
    analyze_parser.add_argument(
        "--policy-mode",
        choices=["ENFORCE", "ADVISORY", "DISABLED", "enforce", "advisory", "disabled"],
        default=None,
        help="Execution mode for security policies: ENFORCE, ADVISORY, or DISABLED (Phase 23)",
    )
    analyze_parser.add_argument(
        "--explain-policy",
        action="store_true",
        default=False,
        help="Print detailed security policy evaluations and trust boundary evidence in terminal report (Phase 23)",
    )

    # rules subcommand
    rules_parser = subparsers.add_parser(
        "rules",
        help="Inspect registered security and architecture rules",
    )
    rules_parser.add_argument(
        "rule_id",
        nargs="?",
        default=None,
        help="Optional specific rule ID to inspect (e.g. SEC-PY-001, ARC-001)",
    )
    rules_parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)",
    )

    # compare subcommand
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare two CodeSentinel JSON report files (baseline vs current)",
    )
    compare_parser.add_argument(
        "baseline",
        help="Path to baseline JSON report file",
    )
    compare_parser.add_argument(
        "current",
        help="Path to current JSON report file",
    )
    compare_parser.add_argument(
        "--format",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    compare_parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        default=None,
        help="Optional file path to write comparison report to (default: stdout)",
    )
    compare_parser.add_argument(
        "--fail-on-regression",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit code 2 if any newly introduced finding meets or exceeds this severity",
    )

    return parser


def render_terminal_comparison(comparison: ComparisonResult) -> str:
    """Format a ComparisonResult as a clean, high-impact terminal text report."""
    lines = []
    div = "=" * 78
    sub = "-" * 78
    lines.append(div)
    lines.append("  CODESENTINEL BASELINE DIFFERENTIAL REPORT")
    lines.append(div)
    lines.append(f"  Baseline Run ID    : {comparison.baseline_id or 'N/A'}")
    lines.append(f"  Current Run ID     : {comparison.current_id}")
    if comparison.baseline_commit:
        lines.append(f"  Baseline Commit    : {comparison.baseline_commit[:10]}")
    if comparison.current_commit:
        lines.append(f"  Current Commit     : {comparison.current_commit[:10]}")

    lines.append(sub)
    lines.append("  FINDINGS TRANSITION SUMMARY:")
    s = comparison.summary
    lines.append(f"    New Findings (Regressions) : {s.new_count}")
    lines.append(f"    Resolved Findings (Fixed)  : {s.resolved_count}")
    lines.append(f"    Unchanged Findings         : {s.unchanged_count}")
    lines.append(f"    Modified Findings (Shift)  : {s.modified_count}")
    lines.append(f"    Total Baseline Findings    : {s.total_baseline}")
    lines.append(f"    Total Current Findings     : {s.total_current}")

    if comparison.health_delta:
        lines.append(sub)
        hd = comparison.health_delta
        delta_str = f"+{hd.score_delta}" if hd.score_delta >= 0 else str(hd.score_delta)
        lines.append("  CODEBASE HEALTH IMPACT:")
        lines.append(f"    Score Delta                : {delta_str} pts ({hd.baseline_score} -> {hd.current_score})")
        lines.append(f"    Grade Transition           : {hd.baseline_grade or 'N/A'} -> {hd.current_grade or 'N/A'}")
        if hd.architecture_score_delta is not None:
            arch_d_str = f"+{hd.architecture_score_delta}" if hd.architecture_score_delta >= 0 else str(hd.architecture_score_delta)
            lines.append(f"    Architecture Delta         : {arch_d_str} pts")
        if hd.security_score_delta is not None:
            sec_d_str = f"+{hd.security_score_delta}" if hd.security_score_delta >= 0 else str(hd.security_score_delta)
            lines.append(f"    Security Posture Delta     : {sec_d_str} pts")

    if comparison.component_delta:
        cd = comparison.component_delta
        if cd.new_components or cd.removed_components or cd.instability_deltas:
            lines.append(sub)
            lines.append("  COMPONENT TOPOLOGY DELTA:")
            if cd.new_components:
                lines.append(f"    New Components             : {', '.join(cd.new_components)}")
            if cd.removed_components:
                lines.append(f"    Removed Components         : {', '.join(cd.removed_components)}")
            if cd.instability_deltas:
                lines.append("    Instability Deltas         :")
                for c_id, delta in cd.instability_deltas.items():
                    d_str = f"+{delta:.3f}" if delta >= 0 else f"{delta:.3f}"
                    lines.append(f"      {c_id:<28}: {d_str}")

    # List regressions if any
    new_findings = [df for df in comparison.findings if df.transition == FindingTransition.NEW]
    if new_findings:
        lines.append(sub)
        lines.append(f"  NEW REGRESSIONS ({len(new_findings)}):")
        for df in new_findings:
            f = df.finding
            loc = f"{f.location.file_path}:{f.location.line_start or 1}"
            lines.append(f"    [{f.severity.value}] {f.rule_id} at {loc}: {f.message or f.rule_name}")

    # List resolved if any
    resolved_findings = [df for df in comparison.findings if df.transition == FindingTransition.RESOLVED]
    if resolved_findings:
        lines.append(sub)
        lines.append(f"  RESOLVED DEFECTS ({len(resolved_findings)}):")
        for df in resolved_findings:
            f = df.finding
            loc = f"{f.location.file_path}:{f.location.line_start or 1}"
            lines.append(f"    [RESOLVED] {f.rule_id} at {loc}: {f.message or f.rule_name}")

    lines.append(div)
    return "\n".join(lines)


def handle_compare_command(args: argparse.Namespace) -> int:
    """Execute differential comparison between two existing JSON reports."""
    base_p = Path(args.baseline)
    curr_p = Path(args.current)
    if not base_p.is_file():
        sys.stderr.write(f"Comparison Error: Baseline file not found: '{args.baseline}'\n")
        return 1
    if not curr_p.is_file():
        sys.stderr.write(f"Comparison Error: Current file not found: '{args.current}'\n")
        return 1

    try:
        base_data = json.loads(base_p.read_text(encoding="utf-8"))
        baseline_result = AnalysisResult(**base_data)
    except Exception as err:
        sys.stderr.write(f"Comparison Error: Failed to parse baseline JSON '{args.baseline}': {err}\n")
        return 1

    try:
        curr_data = json.loads(curr_p.read_text(encoding="utf-8"))
        current_result = AnalysisResult(**curr_data)
    except Exception as err:
        sys.stderr.write(f"Comparison Error: Failed to parse current JSON '{args.current}': {err}\n")
        return 1

    comparison = BaselineComparator.compare(current=current_result, baseline=baseline_result)

    if args.format == "json":
        report_output = comparison.model_dump_json(indent=2)
    elif args.format == "markdown":
        report_output = MarkdownReporter().render_comparison(comparison)
    else:
        report_output = render_terminal_comparison(comparison)

    if args.output_file:
        try:
            out_p = Path(args.output_file).resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(report_output, encoding="utf-8")
        except Exception as err:
            sys.stderr.write(f"Comparison Error: Failed to write output file '{args.output_file}': {err}\n")
            return 1
    else:
        sys.stdout.write(report_output)
        if not report_output.endswith("\n"):
            sys.stdout.write("\n")

    if args.fail_on_regression:
        sev_val = FindingSeverity(args.fail_on_regression.upper())
        target_rank = SEVERITY_RANKS[sev_val]
        regressions = [
            df.finding for df in comparison.findings
            if df.transition == FindingTransition.NEW and SEVERITY_RANKS.get(df.finding.severity, 0) >= target_rank
        ]
        if regressions:
            sys.stderr.write(
                f"\n[REGRESSION POLICY FAILURE] Found {len(regressions)} newly introduced finding(s) "
                f"with severity >= {sev_val.value}.\n"
            )
            return 2

    return 0


def handle_rules_command(args: argparse.Namespace) -> int:
    """Execute rule inspection command (list mode or single rule detail mode)."""
    registry = RuleRegistry(load_defaults=True)
    all_definitions = registry.get_rule_definitions()

    # Detail mode
    if args.rule_id:
        rule_def = next((d for d in all_definitions if d.rule_id == args.rule_id), None)
        if not rule_def:
            sys.stderr.write(f"Error: Unknown rule ID '{args.rule_id}'.\n")
            return 1

        if args.format == "json":
            dumped = rule_def.model_dump(mode="json", exclude_none=False)
            sys.stdout.write(json.dumps(dumped, indent=2, sort_keys=True) + "\n")
            return 0
        else:
            out: list[str] = []
            divider = "=" * 78
            sub_divider = "-" * 78
            out.append(divider)
            out.append(f"  RULE SPECIFICATION: {rule_def.rule_id} - {rule_def.name}")
            out.append(divider)
            out.append(f"  ID                  : {rule_def.rule_id}")
            out.append(f"  Name                : {rule_def.name}")
            out.append(f"  Category            : {rule_def.category.value}")
            out.append(f"  Severity            : {rule_def.severity.value}")
            out.append(f"  Confidence          : {rule_def.confidence.value}")
            out.append(f"  Evidence Type       : {rule_def.evidence_type.value}")
            if rule_def.supported_languages:
                out.append(f"  Supported Languages : {', '.join(sorted(rule_def.supported_languages))}")
            if rule_def.frameworks:
                out.append(f"  Frameworks          : {', '.join(sorted(rule_def.frameworks))}")
            if rule_def.cwe_id:
                out.append(f"  CWE                 : {rule_def.cwe_id}")
            if rule_def.owasp_category:
                out.append(f"  OWASP               : {rule_def.owasp_category}")
            out.append(sub_divider)
            out.append(f"  Description:\n    {rule_def.description}")
            if rule_def.rationale:
                out.append(f"  Rationale:\n    {rule_def.rationale}")
            out.append(f"  Remediation:\n    {rule_def.remediation}")
            out.append(divider)
            sys.stdout.write("\n".join(out) + "\n")
            return 0

    # List mode
    if args.format == "json":
        sorted_defs = sorted(all_definitions, key=lambda d: d.rule_id)
        dumped = [d.model_dump(mode="json", exclude_none=False) for d in sorted_defs]
        sys.stdout.write(json.dumps(dumped, indent=2, sort_keys=True) + "\n")
        return 0

    # Terminal format list mode
    security_rules = [d for d in all_definitions if d.category == FindingCategory.SECURITY]
    architecture_rules = [d for d in all_definitions if d.category == FindingCategory.ARCHITECTURE]
    security_rules.sort(key=lambda d: d.rule_id)
    architecture_rules.sort(key=lambda d: d.rule_id)

    out = []
    divider = "=" * 78
    sub_divider = "-" * 78
    out.append(divider)
    out.append("  REGISTERED STATIC ANALYSIS RULES")
    out.append(divider)

    if security_rules:
        out.append(f"\n  SECURITY RULES ({len(security_rules)}):")
        out.append("  " + sub_divider)
        out.append(f"  {'Rule ID':<12} {'Severity':<10} {'Confidence':<12} {'Languages':<20} {'Name'}")
        out.append("  " + sub_divider)
        for r in security_rules:
            langs = ", ".join(r.supported_languages) if r.supported_languages else "all"
            out.append(f"  {r.rule_id:<12} {r.severity.value:<10} {r.confidence.value:<12} {langs:<20} {r.name}")

    if architecture_rules:
        out.append(f"\n  ARCHITECTURE RULES ({len(architecture_rules)}):")
        out.append("  " + sub_divider)
        out.append(f"  {'Rule ID':<12} {'Severity':<10} {'Confidence':<12} {'Languages':<20} {'Name'}")
        out.append("  " + sub_divider)
        for r in architecture_rules:
            langs = ", ".join(r.supported_languages) if r.supported_languages else "all"
            out.append(f"  {r.rule_id:<12} {r.severity.value:<10} {r.confidence.value:<12} {langs:<20} {r.name}")

    out.append("\n" + divider)
    out.append(f"  Total Registered Rules: {len(all_definitions)}")
    out.append(divider)
    sys.stdout.write("\n".join(out) + "\n")
    return 0


def _sync_analysis_to_backend(result: AnalysisResult, target_path: str, api_url: str) -> None:
    """Optional synchronization helper to persist AnalysisResult to CodeSentinel backend API."""
    import json
    import urllib.error
    import urllib.request

    base_url = api_url.rstrip("/")
    resolved_path = str(Path(target_path).resolve())
    repo_name = Path(resolved_path).name

    try:
        # Step 1: Register or get repository
        reg_url = f"{base_url}/api/v1/repositories"
        reg_payload = json.dumps({"path": resolved_path, "name": repo_name}).encode("utf-8")
        req = urllib.request.Request(
            reg_url,
            data=reg_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            repo_data = json.loads(resp.read().decode("utf-8"))
            repo_id = repo_data["id"]

        # Step 2: Post snapshot
        snapshot_url = f"{base_url}/api/v1/repositories/{repo_id}/snapshots"
        snap_payload = result.model_dump_json().encode("utf-8")
        snap_req = urllib.request.Request(
            snapshot_url,
            data=snap_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(snap_req, timeout=10) as snap_resp:
            snap_data = json.loads(snap_resp.read().decode("utf-8"))
            sys.stderr.write(f"[Persistence Sync] Successfully saved snapshot '{snap_data['id']}' to backend ({base_url})\n")
    except Exception as exc:
        sys.stderr.write(f"[Persistence Sync Warning] Failed to persist snapshot to {base_url}: {exc}\n")


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI execution entrypoint.
    
    Exit codes:
      0: Analysis completed cleanly, policy passed (or no policy).
      1: Operational error (invalid path, permission error, configuration conflict/unknown rule, report write error).
      2: Policy failure (one or more findings meet or exceed --fail-on severity threshold).
    """
    if argv is None:
        argv = sys.argv[1:]

    # Ergonomic shortcut: if first arg is not a subcommand or option flag, route to 'analyze'
    if argv and not argv[0].startswith("-") and argv[0] not in ("analyze", "help", "rules", "compare"):
        effective_argv = ["analyze"] + argv
    else:
        effective_argv = argv

    parser = build_parser()

    # If no arguments provided at all, print help and exit 1
    if not effective_argv:
        parser.print_help(sys.stderr)
        return 1

    try:
        args = parser.parse_args(effective_argv)
    except SystemExit as exc:
        return exc.code

    if args.command == "rules":
        return handle_rules_command(args)

    if args.command == "compare":
        return handle_compare_command(args)

    if args.command != "analyze":
        parser.print_help(sys.stderr)
        return 1

    # Load Repository Configuration (.codesentinel.yml or .codesentinel.json)
    try:
        repo_config, config_file_path, config_hash = load_repo_config(
            target_dir=args.path,
            explicit_config_path=args.config_path,
        )
    except Exception as cfg_err:
        sys.stderr.write(f"Configuration Error: {cfg_err}\n")
        return 1

    target_path = Path(args.path).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Analysis Error: Target path '{args.path}' does not exist.\n")
        return 1

    # Phase 21: Cache Directory resolution
    if getattr(args, "cache_dir", None):
        cache_dir_path = Path(args.cache_dir).resolve()
    else:
        cache_dir_path = target_path / ".codesentinel_cache"

    # Handle --clear-cache
    if getattr(args, "clear_cache", False):
        try:
            cache = DiskAnalysisCache(cache_dir=cache_dir_path)
            cache.clear()
            sys.stdout.write(f"Analysis cache cleared for repository '{target_path.name}'.\n")
            return 0
        except Exception as clr_err:
            sys.stderr.write(f"Cache Error: Failed to clear cache: {clr_err}\n")
            return 1

    # Initialize cache object
    if getattr(args, "no_cache", False):
        analysis_cache = NullAnalysisCache()
    else:
        try:
            analysis_cache = DiskAnalysisCache(cache_dir=cache_dir_path)
        except Exception as cache_err:
            sys.stderr.write(f"Cache Error: Failed to initialize cache at '{cache_dir_path}': {cache_err}\n")
            return 1

    # Apply Three-Tier Precedence: CLI > Repo Config > Defaults
    # Baseline & Regression
    baseline_path = args.baseline_path or (repo_config.comparison.baseline if repo_config else None)
    fail_on_regression = args.fail_on_regression or (repo_config.comparison.fail_on_regression if repo_config else None)

    if fail_on_regression and not baseline_path:
        sys.stderr.write("Configuration Error: --fail-on-regression requires --baseline <file>.\n")
        return 1

    # 1. Parse and validate rules configuration
    cli_enabled = _split_comma_rules(args.enabled_rules) if args.enabled_rules is not None else None
    cli_disabled = _split_comma_rules(args.disabled_rules) if args.disabled_rules is not None else None

    if cli_enabled is not None:
        enabled_rules_list = cli_enabled
    elif repo_config and repo_config.analysis.enabled_rules:
        enabled_rules_list = list(repo_config.analysis.enabled_rules)
    else:
        enabled_rules_list = None

    if cli_disabled:
        disabled_rules_list = cli_disabled
    elif repo_config and repo_config.analysis.disabled_rules:
        disabled_rules_list = list(repo_config.analysis.disabled_rules)
    else:
        disabled_rules_list = []

    # 2. Build Output Format and File
    if args.format:
        output_format_val = args.format.lower()
    elif repo_config and repo_config.reporting.format:
        output_format_val = repo_config.reporting.format.lower()
    else:
        output_format_val = "terminal"

    output_file_val = args.output_file or (repo_config.reporting.output_file if repo_config else None)

    # 3. Build AnalysisConfig
    config_kwargs: dict = {
        "output_format": output_format_val,
        "output_file": output_file_val,
        "disabled_rules": disabled_rules_list,
        "baseline_path": baseline_path,
        "paths_exclude": repo_config.paths.exclude if repo_config else [],
        "config_hash": config_hash,
        "config_file_path": str(config_file_path) if config_file_path else None,
    }
    if enabled_rules_list is not None:
        config_kwargs["enabled_rules"] = enabled_rules_list

    god_module_loc = args.god_module_loc if args.god_module_loc is not None else (repo_config.analysis.god_module_loc if repo_config else None)
    if god_module_loc is not None:
        if god_module_loc < 1:
            sys.stderr.write(f"Error: --god-module-loc must be >= 1, got {god_module_loc}\n")
            return 1
        config_kwargs["arc_003_loc_threshold"] = god_module_loc

    max_component_depth = args.max_component_depth if args.max_component_depth is not None else (repo_config.analysis.max_component_depth if repo_config else None)
    if max_component_depth is not None:
        if max_component_depth < 1:
            sys.stderr.write(f"Error: --max-component-depth must be >= 1, got {max_component_depth}\n")
            return 1
        config_kwargs["max_component_depth"] = max_component_depth

    centrality_threshold = args.centrality_threshold if args.centrality_threshold is not None else (repo_config.analysis.centrality_threshold if repo_config else None)
    if centrality_threshold is not None:
        if centrality_threshold < 0.0 or centrality_threshold > 1.0:
            sys.stderr.write(f"Error: --centrality-threshold must be between 0.0 and 1.0, got {centrality_threshold}\n")
            return 1
        config_kwargs["arc_009_centrality_threshold"] = centrality_threshold

    max_taint_depth = args.max_taint_depth if args.max_taint_depth is not None else (repo_config.analysis.max_taint_depth if repo_config else None)
    if max_taint_depth is not None:
        if max_taint_depth < 1 or max_taint_depth > 100:
            sys.stderr.write(f"Error: --max-taint-depth must be between 1 and 100, got {max_taint_depth}\n")
            return 1
        config_kwargs["max_taint_depth"] = max_taint_depth

    max_call_depth = getattr(args, "max_call_depth", None)
    if max_call_depth is None and repo_config and hasattr(repo_config.analysis, "max_call_depth"):
        max_call_depth = repo_config.analysis.max_call_depth
    if max_call_depth is not None:
        if max_call_depth < 1 or max_call_depth > 20:
            sys.stderr.write(f"Error: --max-call-depth must be between 1 and 20, got {max_call_depth}\n")
            return 1
        config_kwargs["max_call_depth"] = max_call_depth

    disable_interprocedural = bool(getattr(args, "disable_interprocedural", False))
    if not disable_interprocedural and repo_config and hasattr(repo_config.analysis, "interprocedural"):
        disable_interprocedural = not repo_config.analysis.interprocedural
    config_kwargs["disable_interprocedural"] = disable_interprocedural

    disable_type_inference = bool(getattr(args, "disable_type_inference", False))
    if not disable_type_inference and repo_config and hasattr(repo_config.analysis, "disable_type_inference"):
        disable_type_inference = repo_config.analysis.disable_type_inference
    config_kwargs["disable_type_inference"] = disable_type_inference

    disable_context_sensitivity = bool(getattr(args, "disable_context_sensitivity", False))
    if not disable_context_sensitivity and repo_config and hasattr(repo_config.analysis, "disable_context_sensitivity"):
        disable_context_sensitivity = repo_config.analysis.disable_context_sensitivity
    config_kwargs["disable_context_sensitivity"] = disable_context_sensitivity

    max_k = getattr(args, "max_k", None)
    if max_k is None and repo_config and hasattr(repo_config.analysis, "max_k"):
        max_k = repo_config.analysis.max_k
    if max_k is not None:
        if max_k < 1 or max_k > 2:
            sys.stderr.write(f"Error: --max-k must be between 1 and 2, got {max_k}\n")
            return 1
        config_kwargs["max_k"] = max_k

    max_contexts_per_function = getattr(args, "max_contexts_per_function", None)
    if max_contexts_per_function is None and repo_config and hasattr(repo_config.analysis, "max_contexts_per_function"):
        max_contexts_per_function = repo_config.analysis.max_contexts_per_function
    if max_contexts_per_function is not None:
        if max_contexts_per_function < 1 or max_contexts_per_function > 32:
            sys.stderr.write(f"Error: --max-contexts-per-function must be between 1 and 32, got {max_contexts_per_function}\n")
            return 1
        config_kwargs["max_contexts_per_function"] = max_contexts_per_function

    max_summary_iterations = getattr(args, "max_summary_iterations", None)
    if max_summary_iterations is None and repo_config and hasattr(repo_config.analysis, "max_summary_iterations"):
        max_summary_iterations = repo_config.analysis.max_summary_iterations
    if max_summary_iterations is not None:
        if max_summary_iterations < 1 or max_summary_iterations > 20:
            sys.stderr.write(f"Error: --max-summary-iterations must be between 1 and 20, got {max_summary_iterations}\n")
            return 1
        config_kwargs["max_summary_iterations"] = max_summary_iterations

    # Phase 17: Alias, points-to, and field sensitivity config merge
    disable_alias_analysis = bool(getattr(args, "disable_alias_analysis", False))
    if not disable_alias_analysis and repo_config and hasattr(repo_config.analysis, "disable_alias_analysis"):
        disable_alias_analysis = repo_config.analysis.disable_alias_analysis
    config_kwargs["disable_alias_analysis"] = disable_alias_analysis

    disable_field_sensitivity = bool(getattr(args, "disable_field_sensitivity", False))
    if not disable_field_sensitivity and repo_config and hasattr(repo_config.analysis, "disable_field_sensitivity"):
        disable_field_sensitivity = repo_config.analysis.disable_field_sensitivity
    config_kwargs["disable_field_sensitivity"] = disable_field_sensitivity

    max_points_to_candidates = getattr(args, "max_points_to_candidates", None)
    if max_points_to_candidates is None and repo_config and hasattr(repo_config.analysis, "max_points_to_candidates"):
        max_points_to_candidates = repo_config.analysis.max_points_to_candidates
    if max_points_to_candidates is not None:
        if max_points_to_candidates < 1 or max_points_to_candidates > 16:
            sys.stderr.write(f"Error: --max-points-to-candidates must be between 1 and 16, got {max_points_to_candidates}\n")
            return 1
        config_kwargs["max_points_to_candidates"] = max_points_to_candidates

    max_fields_per_object = getattr(args, "max_fields_per_object", None)
    if max_fields_per_object is None and repo_config and hasattr(repo_config.analysis, "max_fields_per_object"):
        max_fields_per_object = repo_config.analysis.max_fields_per_object
    if max_fields_per_object is not None:
        if max_fields_per_object < 1 or max_fields_per_object > 64:
            sys.stderr.write(f"Error: --max-fields-per-object must be between 1 and 64, got {max_fields_per_object}\n")
            return 1
        config_kwargs["max_fields_per_object"] = max_fields_per_object

    max_objects_per_function = getattr(args, "max_objects_per_function", None)
    if max_objects_per_function is None and repo_config and hasattr(repo_config.analysis, "max_objects_per_function"):
        max_objects_per_function = repo_config.analysis.max_objects_per_function
    if max_objects_per_function is not None:
        if max_objects_per_function < 1 or max_objects_per_function > 128:
            sys.stderr.write(f"Error: --max-objects-per-function must be between 1 and 128, got {max_objects_per_function}\n")
            return 1
        config_kwargs["max_objects_per_function"] = max_objects_per_function

    max_alias_iterations = getattr(args, "max_alias_iterations", None)
    if max_alias_iterations is None and repo_config and hasattr(repo_config.analysis, "max_alias_iterations"):
        max_alias_iterations = repo_config.analysis.max_alias_iterations
    if max_alias_iterations is not None:
        if max_alias_iterations < 1 or max_alias_iterations > 20:
            sys.stderr.write(f"Error: --max-alias-iterations must be between 1 and 20, got {max_alias_iterations}\n")
            return 1
        config_kwargs["max_alias_iterations"] = max_alias_iterations

    # Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis config merge
    disable_path_sensitivity = bool(getattr(args, "disable_path_sensitivity", False))
    if not disable_path_sensitivity and repo_config and hasattr(repo_config.analysis, "disable_path_sensitivity"):
        disable_path_sensitivity = repo_config.analysis.disable_path_sensitivity
    config_kwargs["disable_path_sensitivity"] = disable_path_sensitivity

    disable_guard_analysis = bool(getattr(args, "disable_guard_analysis", False))
    if not disable_guard_analysis and repo_config and hasattr(repo_config.analysis, "disable_guard_analysis"):
        disable_guard_analysis = repo_config.analysis.disable_guard_analysis
    config_kwargs["disable_guard_analysis"] = disable_guard_analysis

    max_active_paths = getattr(args, "max_active_paths", None)
    if max_active_paths is None and repo_config and hasattr(repo_config.analysis, "max_active_paths"):
        max_active_paths = repo_config.analysis.max_active_paths
    if max_active_paths is not None:
        if max_active_paths < 1 or max_active_paths > 32:
            sys.stderr.write(f"Error: --max-active-paths must be between 1 and 32, got {max_active_paths}\n")
            return 1
        config_kwargs["max_active_paths"] = max_active_paths

    max_total_path_states = getattr(args, "max_total_path_states", None)
    if max_total_path_states is None and repo_config and hasattr(repo_config.analysis, "max_total_path_states"):
        max_total_path_states = repo_config.analysis.max_total_path_states
    if max_total_path_states is not None:
        if max_total_path_states < 16 or max_total_path_states > 512:
            sys.stderr.write(f"Error: --max-total-path-states must be between 16 and 512, got {max_total_path_states}\n")
            return 1
        config_kwargs["max_total_path_states"] = max_total_path_states

    max_branch_depth = getattr(args, "max_branch_depth", None)
    if max_branch_depth is None and repo_config and hasattr(repo_config.analysis, "max_branch_depth"):
        max_branch_depth = repo_config.analysis.max_branch_depth
    if max_branch_depth is not None:
        if max_branch_depth < 1 or max_branch_depth > 16:
            sys.stderr.write(f"Error: --max-branch-depth must be between 1 and 16, got {max_branch_depth}\n")
            return 1
        config_kwargs["max_branch_depth"] = max_branch_depth

    max_conditions_per_path = getattr(args, "max_conditions_per_path", None)
    if max_conditions_per_path is None and repo_config and hasattr(repo_config.analysis, "max_conditions_per_path"):
        max_conditions_per_path = repo_config.analysis.max_conditions_per_path
    if max_conditions_per_path is not None:
        if max_conditions_per_path < 2 or max_conditions_per_path > 64:
            sys.stderr.write(f"Error: --max-conditions-per-path must be between 2 and 64, got {max_conditions_per_path}\n")
            return 1
        config_kwargs["max_conditions_per_path"] = max_conditions_per_path

    max_cfg_blocks = getattr(args, "max_cfg_blocks", None)
    if max_cfg_blocks is None and repo_config and hasattr(repo_config.analysis, "max_cfg_blocks"):
        max_cfg_blocks = repo_config.analysis.max_cfg_blocks
    if max_cfg_blocks is not None:
        if max_cfg_blocks < 8 or max_cfg_blocks > 256:
            sys.stderr.write(f"Error: --max-cfg-blocks must be between 8 and 256, got {max_cfg_blocks}\n")
            return 1
        config_kwargs["max_cfg_blocks"] = max_cfg_blocks

    # Phase 19: Path-Sensitive Interprocedural Contracts & Function Summaries config merge
    disable_interprocedural_contracts = bool(getattr(args, "disable_interprocedural_contracts", False))
    if not disable_interprocedural_contracts and repo_config and hasattr(repo_config.analysis, "disable_interprocedural_contracts"):
        disable_interprocedural_contracts = repo_config.analysis.disable_interprocedural_contracts
    config_kwargs["disable_interprocedural_contracts"] = disable_interprocedural_contracts

    max_cached_contracts = getattr(args, "max_cached_contracts", None)
    if max_cached_contracts is None and repo_config and hasattr(repo_config.analysis, "max_cached_contracts"):
        max_cached_contracts = repo_config.analysis.max_cached_contracts
    if max_cached_contracts is not None:
        if max_cached_contracts < 100 or max_cached_contracts > 10000:
            sys.stderr.write(f"Error: --max-cached-contracts must be between 100 and 10000, got {max_cached_contracts}\n")
            return 1
        config_kwargs["max_cached_contracts"] = max_cached_contracts

    max_effects_per_summary = getattr(args, "max_effects_per_summary", None)
    if max_effects_per_summary is None and repo_config and hasattr(repo_config.analysis, "max_effects_per_summary"):
        max_effects_per_summary = repo_config.analysis.max_effects_per_summary
    if max_effects_per_summary is not None:
        if max_effects_per_summary < 4 or max_effects_per_summary > 64:
            sys.stderr.write(f"Error: --max-effects-per-summary must be between 4 and 64, got {max_effects_per_summary}\n")
            return 1
        config_kwargs["max_effects_per_summary"] = max_effects_per_summary

    max_field_effect_depth = getattr(args, "max_field_effect_depth", None)
    if max_field_effect_depth is None and repo_config and hasattr(repo_config.analysis, "max_field_effect_depth"):
        max_field_effect_depth = repo_config.analysis.max_field_effect_depth
    if max_field_effect_depth is not None:
        if max_field_effect_depth < 1 or max_field_effect_depth > 8:
            sys.stderr.write(f"Error: --max-field-effect-depth must be between 1 and 8, got {max_field_effect_depth}\n")
            return 1
        config_kwargs["max_field_effect_depth"] = max_field_effect_depth

    # Phase 20: Project-Wide Contract Composition & Security Boundaries config merge
    disable_contract_composition = bool(getattr(args, "disable_contract_composition", False))
    if not disable_contract_composition and repo_config and hasattr(repo_config.analysis, "disable_contract_composition"):
        disable_contract_composition = repo_config.analysis.disable_contract_composition
    config_kwargs["disable_contract_composition"] = disable_contract_composition

    max_contract_composition_depth = getattr(args, "max_contract_composition_depth", None)
    if max_contract_composition_depth is None and repo_config and hasattr(repo_config.analysis, "max_contract_composition_depth"):
        max_contract_composition_depth = repo_config.analysis.max_contract_composition_depth
    if max_contract_composition_depth is not None:
        if max_contract_composition_depth < 1 or max_contract_composition_depth > 16:
            sys.stderr.write(f"Error: --max-contract-composition-depth must be between 1 and 16, got {max_contract_composition_depth}\n")
            return 1
        config_kwargs["max_contract_composition_depth"] = max_contract_composition_depth

    max_exception_contracts = getattr(args, "max_exception_contracts", None)
    if max_exception_contracts is None and repo_config and hasattr(repo_config.analysis, "max_exception_contracts"):
        max_exception_contracts = repo_config.analysis.max_exception_contracts
    if max_exception_contracts is not None:
        if max_exception_contracts < 1 or max_exception_contracts > 64:
            sys.stderr.write(f"Error: --max-exception-contracts must be between 1 and 64, got {max_exception_contracts}\n")
            return 1
        config_kwargs["max_exception_contracts"] = max_exception_contracts

    max_contract_conflicts = getattr(args, "max_contract_conflicts", None)
    if max_contract_conflicts is None and repo_config and hasattr(repo_config.analysis, "max_contract_conflicts"):
        max_contract_conflicts = repo_config.analysis.max_contract_conflicts
    if max_contract_conflicts is not None:
        if max_contract_conflicts < 1 or max_contract_conflicts > 128:
            sys.stderr.write(f"Error: --max-contract-conflicts must be between 1 and 128, got {max_contract_conflicts}\n")
            return 1
        config_kwargs["max_contract_conflicts"] = max_contract_conflicts

    max_container_fields = getattr(args, "max_container_fields", None)
    if max_container_fields is None and repo_config and hasattr(repo_config.analysis, "max_container_fields"):
        max_container_fields = repo_config.analysis.max_container_fields
    if max_container_fields is not None:
        if max_container_fields < 1 or max_container_fields > 64:
            sys.stderr.write(f"Error: --max-container-fields must be between 1 and 64, got {max_container_fields}\n")
            return 1
        config_kwargs["max_container_fields"] = max_container_fields

    max_project_contract_nodes = getattr(args, "max_project_contract_nodes", None)
    if max_project_contract_nodes is None and repo_config and hasattr(repo_config.analysis, "max_project_contract_nodes"):
        max_project_contract_nodes = repo_config.analysis.max_project_contract_nodes
    if max_project_contract_nodes is not None:
        if max_project_contract_nodes < 50 or max_project_contract_nodes > 10000:
            sys.stderr.write(f"Error: --max-project-contract-nodes must be between 50 and 10000, got {max_project_contract_nodes}\n")
            return 1
        config_kwargs["max_project_contract_nodes"] = max_project_contract_nodes

    fail_on = args.fail_on or (repo_config.analysis.fail_on if repo_config else None)
    if fail_on:
        config_kwargs["fail_on_severity"] = fail_on.upper()

    if fail_on_regression:
        config_kwargs["fail_on_regression"] = fail_on_regression.upper()

    if getattr(args, "policy_mode", None):
        config_kwargs["policy_mode"] = args.policy_mode.upper()

    try:
        analysis_config = AnalysisConfig(**config_kwargs)
    except Exception as conf_err:
        sys.stderr.write(f"Configuration Error: {conf_err}\n")
        return 1

    # 4. Execute Analysis Pipeline
    analysis_mode = "incremental" if getattr(args, "incremental", False) else "full"
    try:
        if getattr(args, "verify_equivalence", False):
            # Run full and incremental sequentially, compare equivalence
            full_pipeline = AnalysisPipeline()
            full_result = full_pipeline.run(
                target_path=args.path,
                analysis_config=analysis_config,
                mode="full",
                cache=analysis_cache,
            )
            inc_pipeline = AnalysisPipeline()
            inc_result = inc_pipeline.run(
                target_path=args.path,
                analysis_config=analysis_config,
                mode="incremental",
                cache=analysis_cache,
            )
            equiv = EquivalenceChecker.compare(full_result=full_result, incremental_result=inc_result)
            if not equiv.is_equivalent:
                sys.stderr.write(f"[EQUIVALENCE VERIFICATION FAILED] Discrepancies: {equiv.discrepancies}\n")
                return 1
            result = inc_result
        else:
            pipeline = AnalysisPipeline()
            result = pipeline.run(
                target_path=args.path,
                analysis_config=analysis_config,
                mode=analysis_mode,
                cache=analysis_cache,
            )
    except (FileNotFoundError, ValueError, PermissionError, RuntimeError) as run_err:
        sys.stderr.write(f"Analysis Error: {run_err}\n")
        return 1
    except Exception as unhandled_err:
        sys.stderr.write(f"Unexpected Engine Error: {unhandled_err}\n")
        return 1

    # 5. Apply filtering if requested (CLI > repo config)
    filter_category = args.category or (repo_config.reporting.category if repo_config else None)
    filter_severity = args.severity or (repo_config.reporting.severity if repo_config else None)
    filter_rules = args.rule_filters

    has_filters = bool(filter_category or filter_severity or filter_rules)
    if has_filters:
        filtered_sec = list(result.security_findings)
        filtered_arch = list(result.architecture_findings)

        if filter_category:
            cat_norm = filter_category.upper()
            if cat_norm == "SECURITY":
                filtered_arch = []
            elif cat_norm == "ARCHITECTURE":
                filtered_sec = []

        if filter_severity:
            sev_rank = SEVERITY_RANKS[FindingSeverity(filter_severity.upper())]
            filtered_sec = [f for f in filtered_sec if SEVERITY_RANKS.get(f.severity, 0) >= sev_rank]
            filtered_arch = [f for f in filtered_arch if SEVERITY_RANKS.get(f.severity, 0) >= sev_rank]

        if filter_rules:
            target_rule_ids = {r.upper() for r in _split_comma_rules(filter_rules)}
            filtered_sec = [f for f in filtered_sec if f.rule_id.upper() in target_rule_ids]
            filtered_arch = [f for f in filtered_arch if f.rule_id.upper() in target_rule_ids]

        def _sort_finding(f):
            return (
                -SEVERITY_RANKS.get(f.severity, 0),
                f.location.file_path,
                f.location.line_start or 0,
                f.rule_id,
            )

        filtered_sec.sort(key=_sort_finding)
        filtered_arch.sort(key=_sort_finding)

        result.security_findings = filtered_sec
        result.architecture_findings = filtered_arch
        result.security_summary.total = len(filtered_sec)
        result.security_summary.critical = sum(1 for f in filtered_sec if f.severity == FindingSeverity.CRITICAL)
        result.security_summary.high = sum(1 for f in filtered_sec if f.severity == FindingSeverity.HIGH)
        result.security_summary.medium = sum(1 for f in filtered_sec if f.severity == FindingSeverity.MEDIUM)
        result.security_summary.low = sum(1 for f in filtered_sec if f.severity == FindingSeverity.LOW)
        result.security_summary.info = sum(1 for f in filtered_sec if f.severity == FindingSeverity.INFO)
        result.architecture_summary.total_findings = len(filtered_arch)

    # 6. Perform Baseline Comparison if requested
    comparison: Optional[ComparisonResult] = None
    if baseline_path:
        base_p = Path(baseline_path).resolve()
        if not base_p.is_file():
            sys.stderr.write(f"Baseline Error: Baseline file not found: '{baseline_path}'\n")
            return 1
        try:
            base_data = json.loads(base_p.read_text(encoding="utf-8"))
            baseline_result = AnalysisResult(**base_data)
            comparison = BaselineComparator.compare(current=result, baseline=baseline_result)
        except Exception as err:
            sys.stderr.write(f"Baseline Error: Failed to process baseline JSON '{baseline_path}': {err}\n")
            return 1

    # 7. Render Report
    if analysis_config.output_format == OutputFormat.JSON:
        reporter = JsonReporter()
    elif analysis_config.output_format == OutputFormat.SARIF:
        reporter = SarifReporter()
    elif analysis_config.output_format == OutputFormat.HTML:
        reporter = HtmlReporter()
    elif analysis_config.output_format == OutputFormat.MARKDOWN:
        reporter = MarkdownReporter()
    elif analysis_config.output_format == OutputFormat.JUNIT:
        reporter = JunitReporter()
    elif analysis_config.output_format == OutputFormat.GITLAB:
        reporter = GitlabReporter()
    else:
        reporter = TerminalReporter()

    try:
        if comparison and analysis_config.output_format == OutputFormat.MARKDOWN:
            report_output = reporter.render_comparison(comparison)
        else:
            report_output = reporter.render(result)
            if comparison and analysis_config.output_format == OutputFormat.TERMINAL:
                report_output += "\n\n" + render_terminal_comparison(comparison)
    except Exception as render_err:
        sys.stderr.write(f"Reporting Render Error: {render_err}\n")
        return 1

    # 8. Output Report (stdout or file)
    target_output_file = output_file_val
    if target_output_file:
        try:
            out_path = Path(target_output_file).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report_output, encoding="utf-8")
        except Exception as write_err:
            sys.stderr.write(f"Error writing report to '{target_output_file}': {write_err}\n")
            return 1
    else:
        # Print directly to stdout
        sys.stdout.write(report_output)
        if not report_output.endswith("\n"):
            sys.stdout.write("\n")

    # 8c. Phase 21: Display Cache Statistics if requested
    if getattr(args, "cache_stats", False):
        stats_data = None
        if result.call_graph_summary and "incremental_stats" in result.call_graph_summary:
            stats_data = result.call_graph_summary["incremental_stats"]
        elif hasattr(result, "incremental_stats") and result.incremental_stats:
            stats_data = result.incremental_stats

        if stats_data:
            stats_output = render_incremental_stats_table(stats_data)
        else:
            from analyzer.incremental.models import IncrementalStats
            fallback = IncrementalStats(
                analysis_mode=analysis_mode,
                files_discovered=result.repository.total_files,
                files_reanalyzed=result.repository.total_files,
            )
            stats_output = render_incremental_stats_table(fallback)

        sys.stdout.write("\n" + stats_output + "\n")

    # 8b. Optional persistence synchronization (Phase 10)
    if getattr(args, "save", False):
        _sync_analysis_to_backend(result, args.path, getattr(args, "api_url", "http://localhost:8000"))

    # 9. Evaluate Policy Thresholds
    # 9a. Standard fail-on
    if analysis_config.fail_on_severity:
        threshold_rank = SEVERITY_RANKS[analysis_config.fail_on_severity]
        all_findings = result.security_findings + result.architecture_findings
        failing_findings = [
            f for f in all_findings
            if SEVERITY_RANKS.get(f.severity, 0) >= threshold_rank
        ]

        if failing_findings:
            sys.stderr.write(
                f"\n[POLICY FAILURE] Found {len(failing_findings)} finding(s) with severity "
                f">= {analysis_config.fail_on_severity.value}.\n"
            )
            return 2

    # 9b. Differential fail-on-regression (Phase 9)
    if fail_on_regression and comparison is not None:
        target_sev = FindingSeverity(fail_on_regression.upper())
        threshold_rank = SEVERITY_RANKS[target_sev]
        regressions = [
            df.finding for df in comparison.findings
            if df.transition == FindingTransition.NEW and SEVERITY_RANKS.get(df.finding.severity, 0) >= threshold_rank
        ]

        if regressions:
            sys.stderr.write(
                f"\n[REGRESSION POLICY FAILURE] Found {len(regressions)} newly introduced finding(s) "
                f"with severity >= {target_sev.value}.\n"
            )
            return 2

    return 0

if __name__ == "__main__":
    sys.exit(main())
