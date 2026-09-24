"""JUnit XML report generator for CI/CD test runner integration (Phase 14)."""

import html
from typing import Optional
from xml.sax.saxutils import escape as xml_escape, quoteattr as xml_quoteattr

from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter

SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 5,
    FindingSeverity.HIGH: 4,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFO: 1,
}


def _esc(text: Optional[str]) -> str:
    """Escape text for XML element body."""
    if not text:
        return ""
    return xml_escape(str(text))


class JunitReporter(BaseReporter):
    """Generates standard JUnit XML reports compatible with Jenkins, GitLab, Azure DevOps."""

    def __init__(self, failure_threshold: Optional[FindingSeverity] = None):
        self.failure_threshold = failure_threshold

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a schema-valid JUnit XML report."""
        all_findings = sorted(
            result.security_findings + result.architecture_findings,
            key=lambda f: (f.location.file_path, f.location.line_start or 0, f.rule_id),
        )

        min_rank = SEVERITY_ORDER.get(self.failure_threshold, 1) if self.failure_threshold else 1
        failures_count = sum(1 for f in all_findings if SEVERITY_ORDER.get(f.severity, 0) >= min_rank)
        total_tests = len(all_findings) if all_findings else 1

        duration_str = f"{result.metadata.duration_seconds:.3f}" if result.metadata.duration_seconds is not None else "0.000"
        timestamp_str = (result.metadata.completed_at or result.metadata.started_at).isoformat()
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuites name="CodeSentinel" tests="{total_tests}" failures="{failures_count}" errors="0" time="{duration_str}">',
            f'  <testsuite name="Static Analysis" tests="{total_tests}" failures="{failures_count}" errors="0" time="{duration_str}" timestamp="{timestamp_str}">',
        ]

        if not all_findings:
            # Emits single passing testcase when repository is clean
            lines.append('    <testcase classname="codesentinel.audit" name="CleanCodebase" time="0.001"/>')
        else:
            for f in all_findings:
                category_name = f.category.value.lower()
                classname = f"codesentinel.{category_name}"
                test_name = f"{f.rule_id} in {f.location.file_path}:{f.location.line_start or 1}"
                file_attr = f.location.file_path
                line_attr = str(f.location.line_start or 1)

                is_failure = SEVERITY_ORDER.get(f.severity, 0) >= min_rank

                lines.append(f'    <testcase classname="{xml_escape(classname)}" name="{xml_escape(test_name)}" file="{xml_escape(file_attr)}" line="{line_attr}" time="0.001">')
                if is_failure:
                    msg = f"[{f.severity.value}] {f.rule_name}: {f.message or f.description}"
                    body_parts = [
                        f"Rule ID    : {f.rule_id}",
                        f"Severity   : {f.severity.value}",
                        f"Location   : {f.location.file_path}:{f.location.line_start or 1}",
                        f"Remediation: {f.remediation}",
                    ]
                    if f.code_snippet:
                        body_parts.append(f"\nCode Snippet:\n{f.code_snippet}")
                    if f.evidence and isinstance(f.evidence, dict):
                        if f.evidence.get("path_summary"):
                            body_parts.append(f"\nTaint Path:\n{f.evidence['path_summary']}")
                        if f.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT" and "call_chain" in f.evidence and isinstance(f.evidence["call_chain"], list):
                            chain_lines = []
                            for c_i, s in enumerate(f.evidence["call_chain"], 1):
                                if isinstance(s, dict):
                                    chain_lines.append(f"  {c_i}. {s.get('caller_function')}() -> {s.get('callee_function')}() at {s.get('caller_file')}:{s.get('call_site_line')}")
                            if chain_lines:
                                body_parts.append("\nCall Chain:\n" + "\n".join(chain_lines))

                    failure_body = _esc("\n".join(body_parts))
                    lines.append(f'      <failure message={xml_quoteattr(msg)} type="{xml_escape(f.rule_id)}">{failure_body}</failure>')
                lines.append('    </testcase>')

        lines.append('  </testsuite>')
        lines.append('</testsuites>')
        return "\n".join(lines)
