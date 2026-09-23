"""SEC-PY-009: SQL Injection via Data-Flow."""

import ast
from typing import Any, Optional

from analyzer.dataflow.python_visitor import PythonDataFlowAnalyzer
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.security.base_rule import BaseSecurityRule


class RuleSecPy009(BaseSecurityRule):
    """SEC-PY-009: SQL Injection via Data-Flow."""

    rule_id = "SEC-PY-009"
    name = "SQL Injection via Data-Flow"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["flask", "django", "fastapi", "general"]
    description = (
        "Untrusted user input propagates across variable assignments and reaches a raw SQL execution sink "
        "without parameterized query binding or context-specific numeric validation."
    )
    rationale = (
        "Constructing dynamic SQL queries via multi-step string concatenation or variable assignment "
        "allows external input to alter query syntax, enabling data exfiltration, modification, and privilege escalation."
    )
    remediation = (
        "Use parameterized query placeholders (e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (id,))) "
        "or an ORM instead of dynamic string concatenation."
    )
    cwe_id = "CWE-89"
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

        if isinstance(ast_node, ast.AST):
            tree = ast_node
        else:
            try:
                tree = ast.parse(content, filename=norm_path)
            except SyntaxError:
                return []

        analyzer = PythonDataFlowAnalyzer()
        taint_paths = analyzer.analyze_file(
            tree=tree,
            file_path=norm_path,
            target_rule_id=self.rule_id,
        )

        findings: list[Finding] = []
        for path in taint_paths:
            sink_info = path.sink
            line = sink_info.get("line", 1)
            col = sink_info.get("column", 0)

            # Extract snippet around sink line
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

            msg = f"SQL Injection via Data-Flow: {path.path_summary}"
            finding = self.create_finding(
                location=location,
                code_snippet=snippet,
                custom_description=msg,
                message=msg,
                evidence=evidence_dict,
            )
            findings.append(finding)

        return findings
