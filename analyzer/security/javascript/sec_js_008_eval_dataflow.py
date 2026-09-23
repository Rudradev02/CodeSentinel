"""SEC-JS-008: Dynamic Code Execution via Data-Flow."""

from typing import Any, Optional
from tree_sitter import Node

from analyzer.dataflow.js_visitor import JSDataFlowAnalyzer
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.rules.js_ast_helper import parse_js_ts_source
from analyzer.security.base_rule import BaseSecurityRule


class RuleSecJs008(BaseSecurityRule):
    """SEC-JS-008: Dynamic Code Execution via Data-Flow."""

    rule_id = "SEC-JS-008"
    name = "Dynamic Code Execution via Data-Flow"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.CRITICAL
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react", "express"]
    description = (
        "Untrusted inputs propagate across variable assignments into dynamic script evaluation sinks "
        "(eval() or Function() constructor) without validation."
    )
    rationale = (
        "Executing dynamic expressions carrying untrusted data grants attackers arbitrary script execution "
        "within the application runtime, bypassing security boundaries."
    )
    remediation = (
        "Avoid dynamic script evaluation. Use structured data formats (e.g. JSON.parse()) and static function dispatch."
    )
    cwe_id = "CWE-95"
    owasp_category = "A03:2021-Injection"

    def analyze(
        self,
        file_path: str,
        content: str,
        ast_node: Optional[Any] = None,
        **kwargs: Any,
    ) -> list[Finding]:
        norm_path = file_path.replace("\\", "/")
        lines = content.splitlines()

        if isinstance(ast_node, Node):
            root_node = ast_node
            source_bytes = content.encode("utf-8", errors="replace")
        else:
            try:
                root_node, source_bytes = parse_js_ts_source(norm_path, content)
            except Exception:
                return []

        analyzer = JSDataFlowAnalyzer()
        taint_paths = analyzer.analyze_file(
            root_node=root_node,
            source_bytes=source_bytes,
            file_path=norm_path,
            target_rule_id=self.rule_id,
        )

        findings: list[Finding] = []
        for path in taint_paths:
            sink_info = path.sink
            line = sink_info.get("line", 1)
            col = sink_info.get("column", 0)

            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else sink_info.get("callee", "")
            location = SourceLocation(
                file_path=norm_path,
                line_start=line,
                line_end=line,
                col_start=col,
                col_end=col + len(snippet),
            )

            evidence_dict = {
                "flow_type": path.flow_type,
                "source": path.source,
                "propagation": path.propagation,
                "sanitizer": path.sanitizer,
                "sink": path.sink,
                "path_summary": path.path_summary,
            }

            msg = f"Dynamic Code Execution via Data-Flow: {path.path_summary}"
            finding = self.create_finding(
                location=location,
                code_snippet=snippet,
                custom_description=msg,
                message=msg,
                evidence=evidence_dict,
            )
            findings.append(finding)

        return findings
