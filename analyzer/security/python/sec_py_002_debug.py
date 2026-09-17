"""SEC-PY-002: Production DEBUG Enabled."""

import ast
from typing import Any, Optional

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.security.base_rule import BaseSecurityRule


class SecPy002Visitor(ast.NodeVisitor):
    """AST visitor detecting DEBUG = True or app.run(debug=True)."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            target_name = None
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start) or line_start
                    col_start = getattr(node, "col_offset", 0)
                    col_end = getattr(node, "end_col_offset", None)
                    snippet = self.lines[line_start - 1].strip() if 0 <= line_start - 1 < len(self.lines) else "DEBUG = True"

                    location = SourceLocation(
                        file_path=self.file_path,
                        line_start=line_start,
                        line_end=line_end,
                        col_start=col_start,
                        col_end=col_end,
                    )
                    evidence = {
                        "trigger": "DEBUG = True",
                        "framework": "django" if "django" in self.file_path.lower() else "general",
                    }
                    self.findings.append(
                        self.rule.create_finding(
                            location=location,
                            code_snippet=snippet,
                            custom_description=(
                                "Explicit 'DEBUG = True' setting detected. Enabling debug mode in production "
                                "exposes detailed stack traces, environment variables, and interactive debug consoles."
                            ),
                            message="Production DEBUG mode enabled",
                            explanation=(
                                "Explicit 'DEBUG = True' setting detected. Enabling debug mode in production "
                                "exposes detailed stack traces, environment variables, and interactive debug consoles."
                            ),
                            evidence=evidence,
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check app.run(..., debug=True)
        is_run_call = False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            is_run_call = True
        elif isinstance(node.func, ast.Name) and node.func.id == "run":
            is_run_call = True

        if is_run_call:
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start) or line_start
                    col_start = getattr(node, "col_offset", 0)
                    col_end = getattr(node, "end_col_offset", None)
                    snippet = self.lines[line_start - 1].strip() if 0 <= line_start - 1 < len(self.lines) else "app.run(debug=True)"

                    location = SourceLocation(
                        file_path=self.file_path,
                        line_start=line_start,
                        line_end=line_end,
                        col_start=col_start,
                        col_end=col_end,
                    )
                    evidence = {
                        "trigger": "app.run(debug=True)",
                        "framework": "flask",
                    }
                    self.findings.append(
                        self.rule.create_finding(
                            location=location,
                            code_snippet=snippet,
                            custom_description=(
                                "Flask application launched with 'debug=True'. Running a debug server in production "
                                "enables the interactive Werkzeug debugger which can permit arbitrary remote code execution."
                            ),
                            message="Flask application launched with debug=True",
                            explanation=(
                                "Flask application launched with 'debug=True'. Running a debug server in production "
                                "enables the interactive Werkzeug debugger which can permit arbitrary remote code execution."
                            ),
                            evidence=evidence,
                        )
                    )
        self.generic_visit(node)


class RuleSecPy002(BaseSecurityRule):
    """SEC-PY-002: Production DEBUG Enabled."""

    rule_id = "SEC-PY-002"
    name = "Production DEBUG Enabled"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["django", "flask", "general"]
    description = (
        "Detected explicit DEBUG mode enabled (DEBUG = True or app.run(debug=True))."
    )
    rationale = (
        "Enabling debug mode in production environments leaks detailed tracebacks, source code snippets, "
        "and environment variables, and enables interactive remote debugging capabilities."
    )
    remediation = (
        "Ensure DEBUG is disabled in production environments. Read the debug setting "
        "from an environment variable (e.g., DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1'))."
    )
    cwe_id = "CWE-489"
    owasp_category = "A05:2021-Security Misconfiguration"

    def analyze(
        self,
        file_path: str,
        content: str,
        ast_node: Optional[Any] = None,
        **kwargs: Any,
    ) -> list[Finding]:
        norm_path = file_path.replace("\\", "/")
        lines = content.splitlines()

        tree = ast_node
        if tree is None or not isinstance(tree, ast.AST):
            try:
                tree = ast.parse(content, filename=file_path)
            except Exception:
                return []

        visitor = SecPy002Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
