"""OASIS SARIF v2.1.0 compliant reporter for CodeSentinel static analysis findings."""

import json
from pathlib import Path
from typing import Any

from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter
from analyzer.rules.registry import RuleRegistry

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# SARIF severity level mapping
SEVERITY_TO_SARIF_LEVEL: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}


def _normalize_uri(path_str: str) -> str:
    """Normalize file path to POSIX relative URI."""
    return path_str.replace("\\", "/").lstrip("/")


def _to_pascal_case(text: str) -> str:
    """Convert a rule name or identifier into clean PascalCase."""
    clean = "".join(ch if ch.isalnum() else " " for ch in text)
    return "".join(word.capitalize() for word in clean.split())


class SarifReporter(BaseReporter):
    """Generates standard OASIS SARIF v2.1.0 JSON reports.
    
    Compatible with:
    - GitHub Code Scanning (actions/upload-sarif)
    - GitLab SAST Reports
    - VS Code SARIF Viewer extension
    - Azure DevOps CodeAnalysis tasks
    """

    def __init__(self):
        self.registry = RuleRegistry(load_defaults=True)

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult as deterministic SARIF 2.1.0 JSON string."""
        all_findings: list[Finding] = result.security_findings + result.architecture_findings

        # Sort findings deterministically
        all_findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line_start or 1,
                f.location.col_start or 0,
                f.rule_id,
            )
        )

        # 1. Collect all rule definitions
        registered_defs = {d.rule_id: d for d in self.registry.get_rule_definitions()}
        
        # Build rule list (sorted deterministically by rule_id)
        sarif_rules: list[dict[str, Any]] = []
        rule_id_to_index: dict[str, int] = {}

        for rule_id in sorted(registered_defs.keys()):
            r_def = registered_defs[rule_id]
            rule_idx = len(sarif_rules)
            rule_id_to_index[rule_id] = rule_idx

            rule_obj: dict[str, Any] = {
                "id": r_def.rule_id,
                "name": _to_pascal_case(r_def.name),
                "shortDescription": {"text": r_def.name},
                "fullDescription": {"text": r_def.description},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(r_def.severity, "warning")
                },
                "help": {
                    "text": f"Remediation Guidance:\n{r_def.remediation}"
                },
                "properties": {
                    "category": r_def.category.value if hasattr(r_def.category, "value") else str(r_def.category),
                    "confidence": r_def.confidence.value if hasattr(r_def.confidence, "value") else str(r_def.confidence),
                },
            }
            if r_def.cwe_id:
                rule_obj["properties"]["cwe"] = r_def.cwe_id
            if r_def.owasp_category:
                rule_obj["properties"]["owasp"] = r_def.owasp_category
            if r_def.rationale:
                rule_obj["properties"]["rationale"] = r_def.rationale

            sarif_rules.append(rule_obj)

        # 2. Build results list
        sarif_results: list[dict[str, Any]] = []
        artifact_uris: set[str] = set()

        for finding in all_findings:
            rel_uri = _normalize_uri(finding.location.file_path)
            artifact_uris.add(rel_uri)

            start_line = finding.location.line_start or 1
            end_line = finding.location.line_end or start_line
            # SARIF columns are 1-based integers
            start_col = (finding.location.col_start + 1) if finding.location.col_start is not None else 1
            end_col = (finding.location.col_end + 1) if finding.location.col_end is not None else None

            region: dict[str, Any] = {
                "startLine": start_line,
                "endLine": end_line,
                "startColumn": start_col,
            }
            if end_col is not None and end_col >= start_col:
                region["endColumn"] = end_col

            if finding.code_snippet:
                region["snippet"] = {"text": finding.code_snippet}

            res_obj: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": finding.message or finding.rule_name
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_uri,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": region,
                        }
                    }
                ],
                "properties": {
                    "findingId": finding.id,
                    "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                    "evidenceType": finding.evidence_type.value if hasattr(finding.evidence_type, "value") else str(finding.evidence_type),
                },
            }

            if finding.rule_id in rule_id_to_index:
                res_obj["ruleIndex"] = rule_id_to_index[finding.rule_id]

            # Phase 13: Map intraprocedural taint paths to SARIF codeFlows
            if finding.evidence and finding.evidence.get("flow_type") == "INTRA_PROCEDURAL_TAINT":
                source_info = finding.evidence.get("source", {})
                sink_info = finding.evidence.get("sink", {})
                propagation = finding.evidence.get("propagation", [])

                thread_flow_locations: list[dict[str, Any]] = []

                if source_info:
                    s_uri = _normalize_uri(source_info.get("file_path", finding.location.file_path))
                    s_line = source_info.get("line", 1)
                    s_col = (source_info.get("column", 0) + 1)
                    s_msg = {"text": f"Source: {source_info.get('expression', 'untrusted input')}"}
                    thread_flow_locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": s_uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": s_line, "startColumn": s_col},
                            },
                            "message": s_msg,
                        },
                        "message": s_msg,
                        "importance": "essential",
                    })

                for step in propagation:
                    p_line = step.get("line", 1)
                    p_col = (step.get("column", 0) + 1)
                    p_expr = step.get("expression", "")
                    p_msg = {"text": f"Propagation ({step.get('operation', 'STEP')}): {p_expr}"}
                    thread_flow_locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": rel_uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": p_line, "startColumn": p_col},
                            },
                            "message": p_msg,
                        },
                        "message": p_msg,
                        "importance": "important",
                    })

                if sink_info:
                    sink_line = sink_info.get("line", start_line)
                    sink_col = (sink_info.get("column", 0) + 1)
                    k_msg = {"text": f"Sink: {sink_info.get('callee', 'sink')}"}
                    thread_flow_locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": rel_uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": sink_line, "startColumn": sink_col},
                            },
                            "message": k_msg,
                        },
                        "message": k_msg,
                        "importance": "essential",
                    })

                if thread_flow_locations:
                    res_obj["codeFlows"] = [
                        {
                            "threadFlows": [
                                {
                                    "locations": thread_flow_locations
                                }
                            ]
                        }
                    ]

            sarif_results.append(res_obj)

        # 3. Assemble SARIF structure
        run_obj: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "CodeSentinel",
                    "semanticVersion": "0.1.0",
                    "informationUri": "https://github.com/Rudradev02/CodeSentinel",
                    "rules": sarif_rules,
                }
            },
            "artifacts": [
                {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
                for uri in sorted(artifact_uris)
            ],
            "results": sarif_results,
        }

        # Embed Git commit / branch provenance if available
        if result.repository.commit_hash:
            vcp: dict[str, Any] = {
                "repositoryUri": result.repository.local_path,
                "revisionId": result.repository.commit_hash,
            }
            if result.repository.branch:
                vcp["branch"] = result.repository.branch
            if result.repository.is_dirty is not None:
                vcp["properties"] = {"isDirty": result.repository.is_dirty}
            run_obj["versionControlProvenance"] = [vcp]

        sarif_document: dict[str, Any] = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [run_obj],
        }

        return json.dumps(sarif_document, indent=2, sort_keys=True)
