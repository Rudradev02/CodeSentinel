"""SEC-JS-007: DOM-Based Cross-Site Scripting (XSS) via Data-Flow."""

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


class RuleSecJs007(BaseSecurityRule):
    """SEC-JS-007: DOM-Based XSS via Data-Flow."""

    rule_id = "SEC-JS-007"
    name = "DOM-Based XSS via Data-Flow"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react", "express"]
    description = (
        "Untrusted DOM inputs (location parameters, cookies, or request properties) propagate across "
        "variable assignments into raw HTML injection sinks (innerHTML, document.write) without sanitization."
    )
    rationale = (
        "Assigning unvalidated dynamic strings to DOM HTML sinks allows external inputs to execute arbitrary "
        "scripts in the victim's browser context, enabling session hijacking and credential theft."
    )
    remediation = (
        "Sanitize HTML using DOMPurify.sanitize() before inserting into the DOM, or assign to safe properties "
        "like textContent."
    )
    cwe_id = "CWE-79"
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

            msg = f"DOM-Based XSS via Data-Flow: {path.path_summary}"
            finding = self.create_finding(
                location=location,
                code_snippet=snippet,
                custom_description=msg,
                message=msg,
                evidence=evidence_dict,
            )
            findings.append(finding)

        return findings
