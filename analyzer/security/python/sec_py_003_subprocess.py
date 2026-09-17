"""SEC-PY-003: Unsafe Subprocess Execution (shell=True)."""

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

SUBPROCESS_FUNCTIONS = {"run", "Popen", "call", "check_call", "check_output"}


class SecPy003Visitor(ast.NodeVisitor):
    """AST visitor detecting subprocess invocations with shell=True and dynamic arguments."""

    def __init__(self, rule: BaseSecurityRule, file_path: str, lines: list[str]):
        self.rule = rule
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []

    def _is_subprocess_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            # subprocess.run, subprocess.Popen, etc.
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                return node.func.attr in SUBPROCESS_FUNCTIONS
            # Also catch os.system
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                return True
        elif isinstance(node.func, ast.Name):
            # direct import: from subprocess import run, Popen
            return node.func.id in SUBPROCESS_FUNCTIONS
        return False

    def _is_dynamic_or_formatted(self, arg_node: ast.expr) -> bool:
        # f-string: f"cat {user_input}"
        if isinstance(arg_node, ast.JoinedStr):
            return True
        # String concatenation or format: "cat " + user_input or "cat %s" % user_input
        if isinstance(arg_node, ast.BinOp):
            return True
        # .format(...) call: "cat {}".format(user_input)
        if isinstance(arg_node, ast.Call):
            if isinstance(arg_node.func, ast.Attribute) and arg_node.func.attr == "format":
                return True
        # Variable name representing dynamic command string: subprocess.run(cmd, shell=True)
        if isinstance(arg_node, ast.Name):
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        if self._is_subprocess_call(node):
            # Special check for os.system which implicitly runs in a shell with dynamic args
            if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                if node.args and self._is_dynamic_or_formatted(node.args[0]):
                    self._emit_finding(node, "os.system() call with dynamic command argument", pattern="os.system", func_name="os.system")
                self.generic_visit(node)
                return

            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_shell_true = True
                    elif isinstance(kw.value, ast.Constant) and kw.value.value == 1:
                        has_shell_true = True

            if has_shell_true:
                # Find command argument (positional arg 0 or args keyword)
                cmd_arg = None
                if node.args:
                    cmd_arg = node.args[0]
                else:
                    for kw in node.keywords:
                        if kw.arg == "args":
                            cmd_arg = kw.value
                            break

                if cmd_arg is not None and self._is_dynamic_or_formatted(cmd_arg):
                    func_name = "subprocess"
                    if isinstance(node.func, ast.Attribute):
                        prefix = getattr(node.func.value, "id", "subprocess")
                        func_name = f"{prefix}.{node.func.attr}"
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    self._emit_finding(
                        node,
                        "subprocess invocation with shell=True and dynamic/formatted command string",
                        pattern="shell=True",
                        func_name=func_name,
                    )

        self.generic_visit(node)

    def _emit_finding(self, node: ast.Call, detail: str, pattern: str = "shell=True", func_name: str = "subprocess.run") -> None:
        line_start = node.lineno
        line_end = getattr(node, "end_lineno", line_start) or line_start
        col_start = getattr(node, "col_offset", 0)
        col_end = getattr(node, "end_col_offset", None)
        snippet = (
            self.lines[line_start - 1].strip()
            if 0 <= line_start - 1 < len(self.lines)
            else "subprocess.run(..., shell=True)"
        )

        location = SourceLocation(
            file_path=self.file_path,
            line_start=line_start,
            line_end=line_end,
            col_start=col_start,
            col_end=col_end,
        )
        evidence = {
            "pattern": pattern,
            "function": func_name,
            "dynamic_argument": True,
        }
        self.findings.append(
            self.rule.create_finding(
                location=location,
                code_snippet=snippet,
                custom_description=(
                    f"Unsafe subprocess execution detected ({detail}). Passing untrusted inputs to "
                    "shell=True permits shell meta-character injection and arbitrary OS command execution (RCE)."
                ),
                message=f"Unsafe subprocess execution via {func_name} ({pattern})",
                explanation=(
                    f"Subprocess call '{func_name}' invokes a shell interpreter with dynamic or formatted arguments. "
                    "Passing unvalidated inputs to shell=True allows command chaining and arbitrary OS command execution."
                ),
                evidence=evidence,
            )
        )


class RuleSecPy003(BaseSecurityRule):
    """SEC-PY-003: Unsafe Subprocess Execution (shell=True)."""

    rule_id = "SEC-PY-003"
    name = "Unsafe Subprocess Execution (shell=True)"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.CRITICAL
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["general", "django", "flask"]
    description = (
        "Detected subprocess execution with shell=True combined with dynamic or formatted arguments."
    )
    rationale = (
        "Invoking system shell interpreters with dynamically formatted command strings allows attackers "
        "to execute arbitrary system commands via shell metacharacters and argument injection."
    )
    remediation = (
        "Pass command arguments as a sequence of strings (e.g. ['cat', filename]) with shell=False. "
        "Avoid invoking the system shell when executing subprocesses."
    )
    cwe_id = "CWE-78"
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

        visitor = SecPy003Visitor(self, norm_path, lines)
        visitor.visit(tree)
        return visitor.findings
