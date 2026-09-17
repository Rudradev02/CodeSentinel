"""SEC-PY-007: Overly Permissive CORS Configuration."""

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

DJANGO_CORS_WILDCARD_VARS = {"CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"}


class SecPy007Visitor(ast.NodeVisitor):
    """AST visitor detecting explicitly permissive CORS wildcard configurations."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check Django CORS_ALLOW_ALL_ORIGINS = True
        for target in node.targets:
            target_name = None
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name in DJANGO_CORS_WILDCARD_VARS:
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start) or line_start
                    col_start = getattr(node, "col_offset", 0)
                    col_end = getattr(node, "end_col_offset", None)
                    snippet = (
                        self.lines[line_start - 1].strip()
                        if 0 <= line_start - 1 < len(self.lines)
                        else f"{target_name} = True"
                    )

                    location = SourceLocation(
                        file_path=self.file_path,
                        line_start=line_start,
                        line_end=line_end,
                        col_start=col_start,
                        col_end=col_end,
                    )
                    evidence = {
                        "origin": "*",
                        "supports_credentials": False,
                    }
                    self.findings.append(
                        self.rule.create_finding(
                            location=location,
                            code_snippet=snippet,
                            custom_description=(
                                f"Permissive CORS configuration '{target_name} = True' detected. Allowing all origins "
                                "enables any external third-party domain to make cross-origin requests to this application."
                            ),
                            message=f"Permissive CORS configuration '{target_name} = True'",
                            explanation=(
                                f"Permissive CORS configuration '{target_name} = True' detected. Allowing all origins "
                                "enables any external third-party domain to make cross-origin requests to this application."
                            ),
                            evidence=evidence,
                        )
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check Flask CORS(app, origins="*", supports_credentials=True) or resources with wildcard and credentials
        is_cors_init = False
        if isinstance(node.func, ast.Name) and node.func.id == "CORS":
            is_cors_init = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "CORS":
            is_cors_init = True

        if is_cors_init:
            has_credentials = False
            has_wildcard_origin = False

            for kw in node.keywords:
                if kw.arg == "supports_credentials" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_credentials = True

                if kw.arg == "origins":
                    if isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                        has_wildcard_origin = True
                    elif isinstance(kw.value, (ast.List, ast.Tuple)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                has_wildcard_origin = True

                # Check resources dictionary for {"origins": "*"}
                if kw.arg == "resources" and isinstance(kw.value, ast.Dict):
                    for val in kw.value.values:
                        if isinstance(val, ast.Dict):
                            for sub_k, sub_v in zip(val.keys, val.values):
                                if isinstance(sub_k, ast.Constant) and sub_k.value == "origins":
                                    if isinstance(sub_v, ast.Constant) and sub_v.value == "*":
                                        has_wildcard_origin = True

            # If wildcard origin is used with credentials, or explicit wildcard origin
            if has_wildcard_origin and has_credentials:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                col_start = getattr(node, "col_offset", 0)
                col_end = getattr(node, "end_col_offset", None)
                snippet = (
                    self.lines[line_start - 1].strip()
                    if 0 <= line_start - 1 < len(self.lines)
                    else "CORS(app, origins='*', supports_credentials=True)"
                )

                location = SourceLocation(
                    file_path=self.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )
                evidence = {
                    "origin": "*",
                    "supports_credentials": True,
                }
                self.findings.append(
                    self.rule.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            "Insecure Flask-CORS configuration: Wildcard origin ('*') enabled alongside "
                            "'supports_credentials=True'. This permits arbitrary external origins to make "
                            "credentialed requests (cookies/authorization headers) to authenticated endpoints."
                        ),
                        message="Insecure CORS: Wildcard origin enabled with credentials",
                        explanation=(
                            "Insecure Flask-CORS configuration: Wildcard origin ('*') enabled alongside "
                            "'supports_credentials=True'. This permits arbitrary external origins to make "
                            "credentialed requests (cookies/authorization headers) to authenticated endpoints."
                        ),
                        evidence=evidence,
                    )
                )

        self.generic_visit(node)


class RuleSecPy007(BaseSecurityRule):
    """SEC-PY-007: Overly Permissive CORS Configuration."""

    rule_id = "SEC-PY-007"
    name = "Overly Permissive CORS Configuration"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["django", "flask"]
    description = (
        "Detected overly permissive CORS configuration allowing wildcard origins with credentials."
    )
    rationale = (
        "Permissive CORS configurations with wildcard origins allow arbitrary external websites to "
        "issue cross-origin requests and read sensitive authenticated responses on behalf of users."
    )
    remediation = (
        "Explicitly specify allowed origins (e.g. CORS_ALLOWED_ORIGINS = ['https://app.example.com']) "
        "and never allow wildcard origins alongside credential sharing."
    )
    cwe_id = "CWE-942"
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

        visitor = SecPy007Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
