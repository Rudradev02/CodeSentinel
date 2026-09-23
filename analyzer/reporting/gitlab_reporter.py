"""GitLab Code Quality JSON report generator (Phase 14)."""

import json
from typing import Any

from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter

GITLAB_SEVERITY_MAP = {
    FindingSeverity.CRITICAL: "critical",
    FindingSeverity.HIGH: "major",
    FindingSeverity.MEDIUM: "minor",
    FindingSeverity.LOW: "info",
    FindingSeverity.INFO: "info",
}


class GitlabReporter(BaseReporter):
    """Generates GitLab Code Quality JSON (gl-code-quality-report.json)."""

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a schema-valid GitLab Code Quality JSON document."""
        all_findings = sorted(
            result.security_findings + result.architecture_findings,
            key=lambda f: (f.location.file_path, f.location.line_start or 0, f.rule_id),
        )

        items: list[dict[str, Any]] = []
        for f in all_findings:
            line_begin = f.location.line_start or 1
            gl_severity = GITLAB_SEVERITY_MAP.get(f.severity, "info")

            item = {
                "description": f"[{f.rule_id}] {f.message or f.description}",
                "check_name": f.rule_id,
                "fingerprint": f.id,
                "severity": gl_severity,
                "location": {
                    "path": f.location.file_path.replace("\\", "/"),
                    "lines": {
                        "begin": line_begin,
                    },
                },
                "categories": [f.category.value],
            }
            items.append(item)

        return json.dumps(items, indent=2)
