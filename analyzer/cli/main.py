import argparse
import json
from pathlib import Path
import sys
from typing import Optional

from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.findings import FindingCategory, FindingSeverity
from analyzer.reporting.json_reporter import JsonReporter
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
        "--format",
        choices=["terminal", "json"],
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
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit with code 2 if any finding has severity equal to or higher than requested severity",
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

    return parser


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
    if argv and not argv[0].startswith("-") and argv[0] not in ("analyze", "help", "rules"):
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

    if args.command != "analyze":
        parser.print_help(sys.stderr)
        return 1

    # 1. Parse and validate rules configuration
    enabled_rules_list = _split_comma_rules(args.enabled_rules) if args.enabled_rules is not None else None
    disabled_rules_list = _split_comma_rules(args.disabled_rules)

    # 2. Build AnalysisConfig
    config_kwargs: dict = {
        "output_format": args.format,
        "output_file": args.output_file,
        "disabled_rules": disabled_rules_list,
    }
    if enabled_rules_list is not None:
        config_kwargs["enabled_rules"] = enabled_rules_list

    if args.god_module_loc is not None:
        if args.god_module_loc < 1:
            sys.stderr.write(f"Error: --god-module-loc must be >= 1, got {args.god_module_loc}\n")
            return 1
        config_kwargs["arc_003_loc_threshold"] = args.god_module_loc

    if args.fail_on:
        config_kwargs["fail_on_severity"] = args.fail_on.upper()

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

    # 4. Render Report
    if analysis_config.output_format == OutputFormat.JSON:
        reporter = JsonReporter()
    else:
        reporter = TerminalReporter()

    try:
        report_output = reporter.render(result)
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

    # 6. Evaluate Policy Threshold (--fail-on)
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
