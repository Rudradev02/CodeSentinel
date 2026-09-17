"""SEC-PY-004: Dangerous Dynamic Code Execution (eval/exec)."""

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


class SecPy004Visitor(ast.NodeVisitor):
    """AST visitor detecting direct calls to built-in eval() or exec()."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None

        # Direct call: eval(...) or exec(...)
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                func_name = node.func.id

        # Qualified built-in call: builtins.eval(...) or __builtins__.eval(...)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ("builtins", "__builtins__"):
                if node.func.attr in ("eval", "exec"):
                    func_name = node.func.attr

        if func_name:
            line_start = node.lineno
            line_end = getattr(node, "end_lineno", line_start) or line_start
            col_start = getattr(node, "col_offset", 0)
            col_end = getattr(node, "end_col_offset", None)
            snippet = (
                self.lines[line_start - 1].strip()
                if 0 <= line_start - 1 < len(self.lines)
                else f"{func_name}(...)"
            )

            location = SourceLocation(
                file_path=self.file_path,
                line_start=line_start,
                line_end=line_end,
                col_start=col_start,
                col_end=col_end,
            )
            evidence = {"callee": func_name}
            self.findings.append(
                self.rule.create_finding(
                    location=location,
                    code_snippet=snippet,
                    custom_description=(
                        f"Dangerous built-in function '{func_name}()' invoked. Evaluating arbitrary or dynamic code "
                        "allows attacker-controlled strings to execute arbitrary Python instructions inside the runtime process."
                    ),
                    message=f"Dangerous dynamic code execution via {func_name}()",
                    explanation=(
                        f"Dangerous built-in function '{func_name}()' invoked. Evaluating arbitrary or dynamic code "
                        "allows attacker-controlled strings to execute arbitrary Python instructions inside the runtime process."
                    ),
                    evidence=evidence,
                )
            )

        self.generic_visit(node)


class RuleSecPy004(BaseSecurityRule):
    """SEC-PY-004: Dangerous Dynamic Code Execution (eval/exec)."""

    rule_id = "SEC-PY-004"
    name = "Dangerous Dynamic Code Execution (eval/exec)"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.CRITICAL
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["general", "django", "flask"]
    description = (
        "Detected direct invocation of built-in eval() or exec() dynamic code execution."
    )
    rationale = (
        "Direct evaluation of strings as Python code using eval/exec allows attackers who influence the "
        "input string to execute arbitrary instructions within the host runtime process."
    )
    remediation = (
        "Replace eval/exec with safe alternatives: use json.loads for serialization, "
        "ast.literal_eval for parsing safe Python literals, or an explicit dispatch dictionary."
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

        tree = ast_node
        if tree is None or not isinstance(tree, ast.AST):
            try:
                tree = ast.parse(content, filename=file_path)
            except Exception:
                return []

        visitor = SecPy004Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
