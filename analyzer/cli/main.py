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
from analyzer.reporting.terminal import TerminalReporter
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
        "config_file_path": config_file_path,
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

    fail_on = args.fail_on or (repo_config.analysis.fail_on if repo_config else None)
    if fail_on:
        config_kwargs["fail_on_severity"] = fail_on.upper()

    if fail_on_regression:
        config_kwargs["fail_on_regression"] = fail_on_regression.upper()

    try:
        analysis_config = AnalysisConfig(**config_kwargs)
    except Exception as conf_err:
        sys.stderr.write(f"Configuration Error: {conf_err}\n")
        return 1

    # 4. Execute Analysis Pipeline
    try:
        pipeline = AnalysisPipeline()
        result = pipeline.run(
            target_path=args.path,
            analysis_config=analysis_config,
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
        "--format",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="Output report format (default: terminal)",
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
        choices=["terminal", "json"],
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

    if args.fail_on_regression and not args.baseline_path:
        sys.stderr.write("Configuration Error: --fail-on-regression requires --baseline <file>.\n")
        return 1

    # 1. Parse and validate rules configuration
    enabled_rules_list = _split_comma_rules(args.enabled_rules) if args.enabled_rules is not None else None
    disabled_rules_list = _split_comma_rules(args.disabled_rules)

    # 2. Build AnalysisConfig
    config_kwargs: dict = {
        "output_format": args.format,
        "output_file": args.output_file,
        "disabled_rules": disabled_rules_list,
        "baseline_path": args.baseline_path,
    }
    if enabled_rules_list is not None:
        config_kwargs["enabled_rules"] = enabled_rules_list

    if args.god_module_loc is not None:
        if args.god_module_loc < 1:
            sys.stderr.write(f"Error: --god-module-loc must be >= 1, got {args.god_module_loc}\n")
            return 1
        config_kwargs["arc_003_loc_threshold"] = args.god_module_loc

    if args.max_component_depth is not None:
        if args.max_component_depth < 1:
            sys.stderr.write(f"Error: --max-component-depth must be >= 1, got {args.max_component_depth}\n")
            return 1
        config_kwargs["max_component_depth"] = args.max_component_depth

    if args.centrality_threshold is not None:
        if args.centrality_threshold < 0.0 or args.centrality_threshold > 1.0:
            sys.stderr.write(f"Error: --centrality-threshold must be between 0.0 and 1.0, got {args.centrality_threshold}\n")
            return 1
        config_kwargs["arc_009_centrality_threshold"] = args.centrality_threshold

    if args.max_taint_depth is not None:
        if args.max_taint_depth < 1 or args.max_taint_depth > 100:
            sys.stderr.write(f"Error: --max-taint-depth must be between 1 and 100, got {args.max_taint_depth}\n")
            return 1
        config_kwargs["max_taint_depth"] = args.max_taint_depth

    if args.fail_on:
        config_kwargs["fail_on_severity"] = args.fail_on.upper()

    if args.fail_on_regression:
        config_kwargs["fail_on_regression"] = args.fail_on_regression.upper()

    try:
        analysis_config = AnalysisConfig(**config_kwargs)
    except Exception as conf_err:
        sys.stderr.write(f"Configuration Error: {conf_err}\n")
        return 1

    # 3. Execute Analysis Pipeline
    try:
        pipeline = AnalysisPipeline()
        result = pipeline.run(
            target_path=args.path,
            analysis_config=analysis_config,
        )
    except (FileNotFoundError, ValueError, PermissionError, RuntimeError) as run_err:
        sys.stderr.write(f"Analysis Error: {run_err}\n")
        return 1
    except Exception as unhandled_err:
        sys.stderr.write(f"Unexpected Engine Error: {unhandled_err}\n")
        return 1

    # 3b. Apply CLI post-analysis filtering if requested
    has_filters = bool(args.category or args.severity or args.rule_filters)
    if has_filters:
        filtered_sec = list(result.security_findings)
        filtered_arch = list(result.architecture_findings)

        if args.category:
            cat_norm = args.category.upper()
            if cat_norm == "SECURITY":
                filtered_arch = []
            elif cat_norm == "ARCHITECTURE":
                filtered_sec = []

        if args.severity:
            sev_rank = SEVERITY_RANKS[FindingSeverity(args.severity.upper())]
            filtered_sec = [f for f in filtered_sec if SEVERITY_RANKS.get(f.severity, 0) >= sev_rank]
            filtered_arch = [f for f in filtered_arch if SEVERITY_RANKS.get(f.severity, 0) >= sev_rank]

        if args.rule_filters:
            target_rule_ids = {r.upper() for r in _split_comma_rules(args.rule_filters)}
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

    # 3c. Perform Baseline Comparison if requested
    comparison: Optional[ComparisonResult] = None
    if args.baseline_path:
        base_p = Path(args.baseline_path).resolve()
        if not base_p.is_file():
            sys.stderr.write(f"Baseline Error: Baseline file not found: '{args.baseline_path}'\n")
            return 1
        try:
            base_data = json.loads(base_p.read_text(encoding="utf-8"))
            baseline_result = AnalysisResult(**base_data)
            comparison = BaselineComparator.compare(current=result, baseline=baseline_result)
        except Exception as err:
            sys.stderr.write(f"Baseline Error: Failed to process baseline JSON '{args.baseline_path}': {err}\n")
            return 1

    # 4. Render Report
    if analysis_config.output_format == OutputFormat.JSON:
        reporter = JsonReporter()
    elif analysis_config.output_format == OutputFormat.SARIF:
        reporter = SarifReporter()
    else:
        reporter = TerminalReporter()

    try:
        report_output = reporter.render(result)
        if comparison and analysis_config.output_format == OutputFormat.TERMINAL:
            report_output += "\n\n" + render_terminal_comparison(comparison)
    except Exception as render_err:
        sys.stderr.write(f"Reporting Render Error: {render_err}\n")
        return 1

    # 5. Output Report (stdout or file)
    if args.output_file:
        try:
            out_path = Path(args.output_file).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report_output, encoding="utf-8")
        except Exception as write_err:
            sys.stderr.write(f"Error writing report to '{args.output_file}': {write_err}\n")
            return 1
    else:
        # Print directly to stdout
        sys.stdout.write(report_output)
        if not report_output.endswith("\n"):
            sys.stdout.write("\n")

    # 5b. Optional persistence synchronization (Phase 10)
    if getattr(args, "save", False):
        _sync_analysis_to_backend(result, args.path, getattr(args, "api_url", "http://localhost:8000"))

    # 6. Evaluate Policy Thresholds
    # 6a. Standard fail-on
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

    # 6b. Differential fail-on-regression (Phase 9)
    if args.fail_on_regression and comparison is not None:
        target_sev = FindingSeverity(args.fail_on_regression.upper())
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
