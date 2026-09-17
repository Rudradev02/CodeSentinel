"""SEC-PY-006: Insecure Cryptographic Hash Functions."""

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

WEAK_HASH_FUNCS = {"md5", "sha1"}


class SecPy006Visitor(ast.NodeVisitor):
    """AST visitor detecting hashlib.md5 or hashlib.sha1 without usedforsecurity=False."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        algorithm_name = None

        # Case 1: hashlib.md5(...) or hashlib.sha1(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr.lower() in WEAK_HASH_FUNCS:
                    algorithm_name = node.func.attr.upper()
                elif node.func.attr == "new" and node.args:
                    # hashlib.new('md5', ...)
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        if first_arg.value.lower() in WEAK_HASH_FUNCS:
                            algorithm_name = first_arg.value.upper()

        # Case 2: from hashlib import md5, sha1; md5(...)
        elif isinstance(node.func, ast.Name):
            if node.func.id.lower() in WEAK_HASH_FUNCS:
                algorithm_name = node.func.id.upper()

        if algorithm_name:
            # Check if usedforsecurity=False is passed
            used_for_security_false = False
            for kw in node.keywords:
                if kw.arg == "usedforsecurity":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        used_for_security_false = True

            if not used_for_security_false:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                col_start = getattr(node, "col_offset", 0)
                col_end = getattr(node, "end_col_offset", None)
                snippet = (
                    self.lines[line_start - 1].strip()
                    if 0 <= line_start - 1 < len(self.lines)
                    else f"hashlib.{algorithm_name.lower()}(...)"
                )

                location = SourceLocation(
                    file_path=self.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )
                evidence = {
                    "algorithm": algorithm_name,
                    "usedforsecurity": False,
                }
                self.findings.append(
                    self.rule.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Insecure cryptographic hash function '{algorithm_name}' invoked without "
                            "usedforsecurity=False. MD5 and SHA1 are vulnerable to practical collision attacks "
                            "and must not be used for security purposes or token generation."
                        ),
                        message=f"Insecure cryptographic hash function '{algorithm_name}'",
                        explanation=(
                            f"Insecure cryptographic hash function '{algorithm_name}' invoked without "
                            "usedforsecurity=False. MD5 and SHA1 are vulnerable to practical collision attacks "
                            "and must not be used for security purposes or token generation."
                        ),
                        evidence=evidence,
                    )
                )

        self.generic_visit(node)


class RuleSecPy006(BaseSecurityRule):
    """SEC-PY-006: Insecure Cryptographic Hash Functions."""

    rule_id = "SEC-PY-006"
    name = "Insecure Cryptographic Hash Functions"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["general", "django", "flask"]
    description = (
        "Detected invocation of weak cryptographic hash function (MD5, SHA-1) without usedforsecurity=False."
    )
    rationale = (
        "MD5 and SHA-1 suffer from known practical cryptographic collision vulnerabilities and should "
        "never be used for digital signatures, token generation, or authentication."
    )
    remediation = (
        "Use modern collision-resistant hash algorithms such as SHA-256 or SHA-3 for digests, "
        "and password-hashing algorithms (Argon2, bcrypt) for password storage. "
        "If used for non-security checksums, explicitly set usedforsecurity=False."
    )
    cwe_id = "CWE-328"
    owasp_category = "A02:2021-Cryptographic Failures"

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

        visitor = SecPy006Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
