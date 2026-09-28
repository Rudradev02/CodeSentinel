"""OWASP CycloneDX v1.5 / v1.6 VEX and security SBOM reporter (Phase 26)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import uuid
from typing import Any, Optional

from analyzer.compliance.catalogs import ALL_COMPLIANCE_CONTROLS
from analyzer.compliance.models import ComplianceAssessmentSuite
from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter

SEVERITY_MAP: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "critical",
    FindingSeverity.HIGH: "high",
    FindingSeverity.MEDIUM: "medium",
    FindingSeverity.LOW: "low",
    FindingSeverity.INFO: "info",
}

CVSS_SCORE_MAP: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 9.5,
    FindingSeverity.HIGH: 8.0,
    FindingSeverity.MEDIUM: 5.5,
    FindingSeverity.LOW: 2.5,
    FindingSeverity.INFO: 0.0,
}


class CycloneDxReporter(BaseReporter):
    """Generates OWASP CycloneDX v1.6 compliant SBOM and VEX vulnerability reports."""

    def __init__(self, spec_version: str = "1.6"):
        self.spec_version = spec_version

    def _extract_cwe_numbers(self, cwe_str: Optional[str]) -> list[int]:
        """Extract integer CWE identifiers from string (e.g., 'CWE-89' -> [89])."""
        if not cwe_str:
            return []
        matches = re.findall(r"\d+", cwe_str)
        return [int(m) for m in matches]

    def _find_compliance_controls_for_rule(self, rule_id: str) -> list[str]:
        """Find all regulatory control IDs mapped to this rule."""
        matched: list[str] = []
        for controls in ALL_COMPLIANCE_CONTROLS.values():
            for c in controls:
                if rule_id in c.mapped_rule_ids:
                    matched.append(c.control_id)
        return matched

    def _format_vulnerability(self, finding: Finding) -> dict[str, Any]:
        """Format an individual Finding into a CycloneDX vulnerability definition."""
        cwe_ints = self._extract_cwe_numbers(finding.cwe_id)
        sev_name = SEVERITY_MAP.get(finding.severity, "medium")
        cvss_val = CVSS_SCORE_MAP.get(finding.severity, 5.0)

        # Stable finding ID
        vuln_id = getattr(finding, "fingerprint", None)
        if vuln_id and hasattr(vuln_id, "stable_id") and vuln_id.stable_id:
            fid = str(vuln_id.stable_id)
        else:
            fid = f"CS-{finding.rule_id}-{finding.id[:8]}"

        # VEX state
        evidence = finding.evidence or {}
        is_suppressed = (
            evidence.get("suppressed") is True
            or evidence.get("is_suppressed") is True
            or evidence.get("lifecycle_state") in ("SUPPRESSED", "DEFERRED")
        )

        analysis_obj: dict[str, Any]
        if is_suppressed:
            analysis_obj = {
                "state": "not_affected",
                "justification": "protected_by_mitigating_control",
                "detail": evidence.get("suppression_reason", "Suppressed via CodeSentinel governance policy"),
            }
        else:
            analysis_obj = {
                "state": "exploitable",
                "detail": "Active unsuppressed security finding requiring remediation",
            }

        properties: list[dict[str, str]] = [
            {"name": "codesentinel:rule_id", "value": finding.rule_id},
            {"name": "codesentinel:category", "value": finding.category.value},
            {"name": "codesentinel:confidence", "value": finding.confidence.value},
            {"name": "codesentinel:file_path", "value": finding.location.file_path},
            {"name": "codesentinel:start_line", "value": str(finding.location.line_start)},
        ]

        mapped_controls = self._find_compliance_controls_for_rule(finding.rule_id)
        for ctrl_id in mapped_controls:
            properties.append({"name": "codesentinel:compliance:control", "value": ctrl_id})

        vuln: dict[str, Any] = {
            "bom-ref": f"vuln-{fid}",
            "id": fid,
            "source": {
                "name": "CodeSentinel Static Analysis",
                "url": "https://codesentinel.dev",
            },
            "ratings": [
                {
                    "source": {"name": "CodeSentinel"},
                    "severity": sev_name,
                    "score": cvss_val,
                    "method": "other",
                }
            ],
            "description": finding.description or finding.rule_name,
            "detail": finding.explanation or finding.description,
            "recommendation": finding.remediation or "Remediate according to security guidelines.",
            "analysis": analysis_obj,
            "affects": [
                {
                    "ref": f"component-{finding.location.file_path}",
                }
            ],
            "properties": properties,
        }

        if cwe_ints:
            vuln["cwes"] = cwe_ints

        return vuln

    def _build_cyclonedx_dict(
        self,
        findings: list[Finding],
        repo_name: str = "Repository",
        timestamp: Optional[str] = None,
        compliance_suite: Optional[ComplianceAssessmentSuite] = None,
    ) -> dict[str, Any]:
        """Construct the complete CycloneDX BOM dictionary."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        # Components
        seen_files: set[str] = set()
        components: list[dict[str, Any]] = []
        for f in findings:
            fp = f.location.file_path
            if fp not in seen_files:
                seen_files.add(fp)
                components.append(
                    {
                        "bom-ref": f"component-{fp}",
                        "type": "file",
                        "name": fp,
                        "description": f"Analyzed repository source file: {fp}",
                    }
                )

        vulnerabilities = [self._format_vulnerability(f) for f in findings]

        metadata: dict[str, Any] = {
            "timestamp": ts,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "vendor": "CodeSentinel",
                        "name": "CodeSentinel Static Analysis Engine",
                        "version": "0.1.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": repo_name,
                "bom-ref": "root-application",
            },
        }

        if compliance_suite:
            compliance_props: list[dict[str, str]] = []
            for fw, res in compliance_suite.framework_results.items():
                compliance_props.append(
                    {"name": f"codesentinel:compliance:{fw}:score", "value": f"{res.overall_score}%"}
                )
                compliance_props.append(
                    {"name": f"codesentinel:compliance:{fw}:status", "value": res.status.value}
                )
        serial_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"codesentinel:{repo_name}:{ts}")

        return {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "serialNumber": f"urn:uuid:{serial_uuid}",
            "version": 1,
            "metadata": metadata,
            "components": components,
            "vulnerabilities": vulnerabilities,
        }

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a formatted CycloneDX JSON report."""
        findings = list(result.findings)
        bom_dict = self._build_cyclonedx_dict(
            findings=findings,
            repo_name=result.repository_path or "TargetRepository",
        )
        return json.dumps(bom_dict, indent=2, sort_keys=True)

    def render_compliance(self, suite: Any) -> str | bytes:
        """Render a ComplianceAssessmentSuite into CycloneDX JSON format."""
        findings: list[Finding] = []
        if hasattr(suite, "framework_results"):
            for res in suite.framework_results.values():
                for ce in res.control_evaluations:
                    findings.extend(ce.violating_findings)
                    findings.extend(ce.suppressed_findings)

        # Deduplicate findings by id
        unique_findings: dict[str, Finding] = {f.id: f for f in findings}
        bom_dict = self._build_cyclonedx_dict(
            findings=list(unique_findings.values()),
            repo_name=suite.repository_path if hasattr(suite, "repository_path") else "Repository",
            compliance_suite=suite if isinstance(suite, ComplianceAssessmentSuite) else None,
        )
        return json.dumps(bom_dict, indent=2, sort_keys=True)
