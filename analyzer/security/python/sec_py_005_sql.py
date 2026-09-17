"""SEC-PY-005: Raw SQL Query String Construction."""

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
from analyzer.security.base_rule import BaseSecurityRule

SQL_KEYWORDS_PATTERN = re.compile(
    r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|WHERE|FROM\s+\w+)\b"
)
SQL_EXECUTE_METHODS = {"execute", "executemany", "raw"}


class SecPy005Visitor(ast.NodeVisitor):
    """AST visitor detecting dynamic/formatted raw SQL query strings."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        """Inspect if any string fragment in the expression contains SQL keywords."""
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if SQL_KEYWORDS_PATTERN.search(part.value):
                        return True
        elif isinstance(node, ast.BinOp):
            # Left or right operand contains SQL
            for operand in (node.left, node.right):
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    if SQL_KEYWORDS_PATTERN.search(operand.value):
                        return True
                elif self._contains_sql_keywords(operand):
                    return True
        elif isinstance(node, ast.Call):
            # "SELECT ... {}".format(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                    if SQL_KEYWORDS_PATTERN.search(node.func.value.value):
                        return True
        return False

    def _detect_dynamic_sql(self, node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.JoinedStr) and self._contains_sql_keywords(node):
            return "f-string"
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)) and self._contains_sql_keywords(node):
            return "string concatenation"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" and self._contains_sql_keywords(node):
            return "str.format()"
        return None

    def visit_Call(self, node: ast.Call) -> None:
        method_name = None
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr

        if method_name in SQL_EXECUTE_METHODS and node.args:
            first_arg = node.args[0]
            construction = self._detect_dynamic_sql(first_arg)
            if construction:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                col_start = getattr(node, "col_offset", 0)
                col_end = getattr(node, "end_col_offset", None)
                snippet = (
                    self.lines[line_start - 1].strip()
                    if 0 <= line_start - 1 < len(self.lines)
                    else "cursor.execute(f'...')"
                )

                location = SourceLocation(
                    file_path=self.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )
                evidence = {
                    "callee": method_name,
                    "construction": construction,
                }
                self.findings.append(
                    self.rule.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Dynamic raw SQL query constructed via {construction} in '{method_name}()'. "
                            "Interpolating variables directly into SQL statements causes SQL Injection (SQLi) "
                            "vulnerabilities if unescaped inputs reach the query."
                        ),
                        message=f"Dynamic raw SQL query construction in '{method_name}()'",
                        explanation=(
                            f"Dynamic raw SQL query constructed via {construction} in '{method_name}()'. "
                            "Interpolating variables directly into SQL statements causes SQL Injection (SQLi) "
                            "vulnerabilities if unescaped inputs reach the query."
                        ),
                        evidence=evidence,
                    )
                )

        self.generic_visit(node)


class RuleSecPy005(BaseSecurityRule):
    """SEC-PY-005: Raw SQL Query String Construction."""

    rule_id = "SEC-PY-005"
    name = "Raw SQL Query String Construction"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.MEDIUM
    languages = ["python"]
    frameworks = ["general", "django", "flask"]
    description = (
        "Detected raw SQL query dynamically constructed via f-string, string concatenation, or format()."
    )
    rationale = (
        "Formatting unescaped user inputs directly into SQL query strings enables SQL Injection (SQLi), "
        "allowing adversaries to alter query structure, read confidential records, or bypass authentication."
    )
    remediation = (
        "Use parameterized query placeholders (e.g. cursor.execute('SELECT * FROM t WHERE id = %s', (val,))) "
        "or higher-level database ORM abstractions (e.g. Django ORM or Peewee models)."
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

        tree = ast_node
        if tree is None or not isinstance(tree, ast.AST):
            try:
                tree = ast.parse(content, filename=file_path)
            except Exception:
                return []

        visitor = SecPy005Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
