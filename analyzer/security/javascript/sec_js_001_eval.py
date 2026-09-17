"""SEC-JS-001: Direct eval() Invocation."""

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


class RuleSecJs001(BaseSecurityRule):
    """SEC-JS-001: Direct eval() Invocation."""

    rule_id = "SEC-JS-001"
    name = "Direct eval() Invocation"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.CRITICAL
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react"]
    description = (
        "Detected direct invocation of eval(). Executing dynamic strings with eval() enables Cross-Site "
        "Scripting (XSS) or arbitrary client-side code execution if input is attacker-influenced."
    )
    rationale = (
        "eval() compiles and executes arbitrary JavaScript strings in the current execution scope, "
        "bypassing Content Security Policy (CSP) protections and introducing high-risk script injection vectors."
    )
    remediation = (
        "Replace eval() with structured parsers (e.g. JSON.parse for JSON payloads) or precompiled "
        "handler functions and object property lookups."
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
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node is None and node.children:
                    func_node = node.children[0]

                is_direct_eval = False
                callee_name = "eval"
                if func_node and func_node.type == "identifier":
                    if node_text(func_node, source_bytes) == "eval":
                        is_direct_eval = True
                        callee_name = "eval"
                elif func_node and func_node.type == "member_expression":
                    # window.eval(...)
                    obj_node = func_node.child_by_field_name("object")
                    prop_node = func_node.child_by_field_name("property")
                    if (
                        obj_node
                        and prop_node
                        and node_text(obj_node, source_bytes) == "window"
                        and node_text(prop_node, source_bytes) == "eval"
                    ):
                        is_direct_eval = True
                        callee_name = "window.eval"

                if is_direct_eval:
                    line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                    snippet = (
                        lines[line_start - 1].strip()
                        if 0 <= line_start - 1 < len(lines)
                        else "eval(...)"
                    )
                    location = SourceLocation(
                        file_path=norm_path,
                        line_start=line_start,
                        line_end=line_end,
                        col_start=col_start,
                        col_end=col_end,
                    )
                    evidence = {"callee": callee_name}
                    findings.append(
                        self.create_finding(
                            location=location,
                            code_snippet=snippet,
                            custom_description=(
                                "Direct 'eval()' invocation detected. Parsing and executing arbitrary code dynamically "
                                "introduces critical injection vulnerabilities and undermines browser security guarantees."
                            ),
                            message=f"Direct '{callee_name}()' invocation",
                            explanation=(
                                f"Direct '{callee_name}()' invocation detected. Parsing and executing arbitrary code dynamically "
                                "introduces critical injection vulnerabilities and undermines browser security guarantees."
                            ),
                            evidence=evidence,
                        )
                    )

        return findings
