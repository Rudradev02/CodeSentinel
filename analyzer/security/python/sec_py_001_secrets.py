"""SEC-PY-001: Hardcoded Secrets & High-Entropy Credentials."""

import ast
import re
from typing import Any, Optional

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.rules.entropy import calculate_shannon_entropy, is_likely_secret_string, redact_secret
from analyzer.security.base_rule import BaseSecurityRule

# Target variable names indicative of security credentials
SECRET_VARIABLE_PATTERN = re.compile(
    r"(?i)(^|_)(secret(_key)?|api(_?key)?|private_key|access_token|auth_token|aws_secret_access_key|client_secret|password|jwt_secret)($|_)"
)


class SecPy001Visitor(ast.NodeVisitor):
    """AST visitor detecting variable assignments with hardcoded high-entropy secrets."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def _check_assignment(self, target_name: str, value_node: ast.expr, node: ast.AST) -> None:
        if not SECRET_VARIABLE_PATTERN.search(target_name):
            return

        # Must be assigned to a string literal
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            str_val = value_node.value
            if is_likely_secret_string(str_val):
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                col_start = getattr(node, "col_offset", 0)
                col_end = getattr(node, "end_col_offset", None)

                # Extract line snippet and redact secret literal
                raw_snippet = self.lines[line_start - 1].strip() if 0 <= line_start - 1 < len(self.lines) else f"{target_name} = '...'"
                redacted_val = redact_secret(str_val)
                safe_snippet = raw_snippet.replace(str_val, redacted_val)
                entropy = calculate_shannon_entropy(str_val)

                location = SourceLocation(
                    file_path=self.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )

                evidence = {
                    "variable_name": target_name,
                    "entropy": round(entropy, 2),
                    "secret_preview": redacted_val,
                }

                finding = self.rule.create_finding(
                    location=location,
                    code_snippet=safe_snippet,
                    custom_description=(
                        f"Hardcoded credential or high-entropy secret detected in variable '{target_name}' "
                        f"(entropy: {entropy:.2f} bits/char). Hardcoded secrets in source control "
                        "risk unauthorized credential exfiltration and compromise."
                    ),
                    message=f"Hardcoded secret detected in '{target_name}'",
                    explanation=(
                        f"Variable '{target_name}' is assigned a high-entropy secret literal (entropy: {entropy:.2f} bits/char). "
                        "Committing credentials to source control exposes them to unauthorized repository readers and potential exfiltration."
                    ),
                    evidence=evidence,
                )
                self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_assignment(target.id, node.value, node)
            elif isinstance(target, ast.Attribute):
                self._check_assignment(target.attr, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            if isinstance(node.target, ast.Name):
                self._check_assignment(node.target.id, node.value, node)
            elif isinstance(node.target, ast.Attribute):
                self._check_assignment(node.target.attr, node.value, node)
        self.generic_visit(node)


class RuleSecPy001(BaseSecurityRule):
    """SEC-PY-001: Detects hardcoded secrets and high-entropy credentials."""

    rule_id = "SEC-PY-001"
    name = "Hardcoded Secrets & High-Entropy Credentials"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["general", "django", "flask"]
    description = (
        "Detected variable assignment containing a hardcoded secret or high-entropy credential literal."
    )
    rationale = (
        "Hardcoded credentials in source control can be extracted by anyone with repository access, "
        "enabling unauthorized lateral movement, API abuse, and data compromise."
    )
    remediation = (
        "Extract sensitive credentials to external environment variables or a secure "
        "secret management system (e.g. AWS Secrets Manager, HashiCorp Vault)."
    )
    cwe_id = "CWE-798"
    owasp_category = "A07:2021-Identification and Authentication Failures"

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

        visitor = SecPy001Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
