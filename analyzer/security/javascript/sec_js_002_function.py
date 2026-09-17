"""SEC-JS-002: Dynamic Function Constructor Execution."""

from typing import Any, Optional
from tree_sitter import Node

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.rules.js_ast_helper import (
    get_node_line_and_col,
    node_text,
    parse_js_ts_source,
    traverse_nodes,
)
from analyzer.security.base_rule import BaseSecurityRule


class RuleSecJs002(BaseSecurityRule):
    """SEC-JS-002: Dynamic Function Constructor Execution."""

    rule_id = "SEC-JS-002"
    name = "Dynamic Function Constructor Execution"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.CRITICAL
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react"]
    description = (
        "Detected dynamic Function constructor execution (new Function() or Function()). "
        "Like eval(), compiling functions from strings allows dynamic code execution and bypasses CSP."
    )
    rationale = (
        "The Function constructor evaluates arbitrary strings into executable functions at runtime, "
        "enabling arbitrary code execution similar to eval() while evading basic security linting."
    )
    remediation = (
        "Refactor dynamic code to use declared JavaScript functions, precompiled handlers, "
        "or static dispatch maps."
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

        if isinstance(ast_node, Node):
            root = ast_node
            source_bytes = content.encode("utf-8", errors="replace")
        else:
            root, source_bytes = parse_js_ts_source(file_path, content)

        findings: list[Finding] = []

        for node in traverse_nodes(root):
            # Target new Function(...) or Function(...)
            is_function_constructor = False

            if node.type == "new_expression":
                ctor_node = node.child_by_field_name("constructor")
                if ctor_node is None and node.children:
                    # In tree-sitter, first child after 'new' keyword is the constructor
                    for c in node.children:
                        if c.type in ("identifier", "member_expression"):
                            ctor_node = c
                            break

                if ctor_node and ctor_node.type == "identifier":
                    if node_text(ctor_node, source_bytes) == "Function":
                        is_function_constructor = True

            elif node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node is None and node.children:
                    func_node = node.children[0]

                if func_node and func_node.type == "identifier":
                    if node_text(func_node, source_bytes) == "Function":
                        is_function_constructor = True

            if is_function_constructor:
                line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                snippet = (
                    lines[line_start - 1].strip()
                    if 0 <= line_start - 1 < len(lines)
                    else "new Function(...)"
                )
                location = SourceLocation(
                    file_path=norm_path,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                )
                evidence = {"constructor": "Function"}
                findings.append(
                    self.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            "Dynamic 'new Function(...)' constructor execution detected. Dynamic function compilation "
                            "from string arguments allows arbitrary script execution similar to eval()."
                        ),
                        message="Dynamic Function constructor execution",
                        explanation=(
                            "Dynamic 'new Function(...)' constructor execution detected. Dynamic function compilation "
                            "from string arguments allows arbitrary script execution similar to eval()."
                        ),
                        evidence=evidence,
                    )
                )

        return findings
