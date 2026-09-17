"""SEC-PY-008: Disabled CSRF Protection via @csrf_exempt."""

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


class SecPy008Visitor(ast.NodeVisitor):
    """AST visitor detecting explicit CSRF protection disablement via @csrf_exempt."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def _check_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            is_exempt = False
            dec_name = None

            # Simple decorator: @csrf_exempt
            if isinstance(decorator, ast.Name) and decorator.id == "csrf_exempt":
                is_exempt = True
                dec_name = "csrf_exempt"

            # Attribute decorator: @views.csrf_exempt or @csrf.exempt
            elif isinstance(decorator, ast.Attribute) and decorator.attr in ("csrf_exempt", "exempt"):
                is_exempt = True
                dec_name = decorator.attr

            # Call decorator: @csrf.exempt()
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name) and decorator.func.id == "csrf_exempt":
                    is_exempt = True
                    dec_name = "csrf_exempt"
                elif isinstance(decorator.func, ast.Attribute) and decorator.func.attr in ("csrf_exempt", "exempt"):
                    is_exempt = True
                    dec_name = decorator.func.attr

            if is_exempt:
                line_start = decorator.lineno
                line_end = getattr(decorator, "end_lineno", line_start) or line_start
                col_start = getattr(decorator, "col_offset", 0)
                col_end = getattr(decorator, "end_col_offset", None)
                snippet = (
                    self.lines[line_start - 1].strip()
                    if 0 <= line_start - 1 < len(self.lines)
                    else f"@{dec_name}"
                )

                location = SourceLocation(
                    file_path=self.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )
                evidence = {
                    "decorator": dec_name,
                    "function": node.name,
                }
                self.findings.append(
                    self.rule.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Explicit CSRF protection disablement '@{dec_name}' on handler '{node.name}()'. "
                            "Disabling CSRF tokens allows malicious third-party websites to forge state-mutating requests "
                            "on behalf of authenticated users (Cross-Site Request Forgery)."
                        ),
                        message=f"Disabled CSRF protection on '{node.name}()' via @{dec_name}",
                        explanation=(
                            f"Handler '{node.name}' is decorated with @{dec_name}, bypassing anti-CSRF token verification "
                            "on state-changing requests and exposing authenticated users to Cross-Site Request Forgery (CSRF)."
                        ),
                        evidence=evidence,
                    )
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_decorators(node)
        self.generic_visit(node)


class RuleSecPy008(BaseSecurityRule):
    """SEC-PY-008: Disabled CSRF Protection via @csrf_exempt."""

    rule_id = "SEC-PY-008"
    name = "Disabled CSRF Protection via @csrf_exempt"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["django", "flask"]
    description = (
        "Detected view handler decorated with @csrf_exempt, explicitly bypassing anti-CSRF token verification."
    )
    rationale = (
        "Exempting endpoints from CSRF token verification allows attacker-controlled web pages to trigger "
        "state-altering requests using authenticated browser session credentials."
    )
    remediation = (
        "Remove @csrf_exempt decorator and require standard anti-CSRF token verification on all "
        "state-changing endpoints (POST, PUT, PATCH, DELETE). For external APIs, enforce token-based "
        "or authorization-header authentication with SameSite cookies."
    )
    cwe_id = "CWE-352"
    owasp_category = "A01:2021-Broken Access Control"

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

        visitor = SecPy008Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
