"""SEC-JS-003: React dangerouslySetInnerHTML Usage."""

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


class RuleSecJs003(BaseSecurityRule):
    """SEC-JS-003: React dangerouslySetInnerHTML Usage."""

    rule_id = "SEC-JS-003"
    name = "React dangerouslySetInnerHTML Usage"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["react"]
    description = (
        "Detected React dangerouslySetInnerHTML attribute assignment without demonstrably sanitized content. "
        "Injecting unescaped HTML into the DOM bypasses React's automatic XSS protection."
    )
    rationale = (
        "dangerouslySetInnerHTML inserts unescaped HTML directly into the DOM tree, "
        "bypassing React's built-in XSS protections and enabling Cross-Site Scripting (XSS)."
    )
    remediation = (
        "Sanitize untrusted HTML inputs with DOMPurify (e.g. DOMPurify.sanitize(content)) "
        "or refactor to native React JSX child elements rather than raw HTML strings."
    )
    cwe_id = "CWE-79"
    owasp_category = "A03:2021-Injection"

    def _is_sanitizer_call(self, node: Node, source_bytes: bytes) -> bool:
        """Check if node is a call to DOMPurify.sanitize(...) or sanitizeHtml(...)."""
        if node.type != "call_expression":
            return False
        func_node = node.child_by_field_name("function")
        if func_node is None and node.children:
            func_node = node.children[0]
        text = node_text(func_node, source_bytes)
        return (
            "DOMPurify.sanitize" in text
            or text == "sanitize"
            or text == "sanitizeHtml"
            or "DOMPurify" in text
        )

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

        # 1. First pass: Collect variables demonstrably initialized from a sanitizer call
        sanitized_identifiers: set[str] = set()
        for node in traverse_nodes(root):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node and value_node and name_node.type == "identifier":
                    if self._is_sanitizer_call(value_node, source_bytes):
                        sanitized_identifiers.add(node_text(name_node, source_bytes))

        # 2. Second pass: Find dangerouslySetInnerHTML attributes
        findings: list[Finding] = []

        for node in traverse_nodes(root):
            if node.type == "jsx_attribute":
                # Find attribute name
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    for child in node.children:
                        if child.type in ("property_identifier", "jsx_identifier", "identifier"):
                            name_node = child
                            break

                if name_node and node_text(name_node, source_bytes) == "dangerouslySetInnerHTML":
                    # Check the assigned value
                    is_sanitized = False

                    value_node = node.child_by_field_name("value")
                    if value_node is None:
                        for child in node.children:
                            if child.type in ("jsx_expression", "string"):
                                value_node = child
                                break

                    if value_node:
                        # Find __html pair inside object
                        for desc in traverse_nodes(value_node):
                            if desc.type == "pair":
                                key_node = desc.child_by_field_name("key")
                                val_node = desc.child_by_field_name("value")
                                if key_node and node_text(key_node, source_bytes) == "__html" and val_node:
                                    # Case A: Direct call to sanitizer
                                    if self._is_sanitizer_call(val_node, source_bytes):
                                        is_sanitized = True
                                    # Case B: Identifier derived from sanitizer
                                    elif val_node.type == "identifier":
                                        ident_name = node_text(val_node, source_bytes)
                                        if ident_name in sanitized_identifiers:
                                            is_sanitized = True

                    if not is_sanitized:
                        line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                        snippet = (
                            lines[line_start - 1].strip()
                            if 0 <= line_start - 1 < len(lines)
                            else "dangerouslySetInnerHTML={...}"
                        )
                        location = SourceLocation(
                            file_path=norm_path,
                            line_start=line_start,
                            line_end=line_end,
                            col_start=col_start,
                            col_end=col_end,
                        )
                        evidence = {
                            "property": "dangerouslySetInnerHTML",
                            "sanitized": False,
                        }
                        findings.append(
                            self.create_finding(
                                location=location,
                                code_snippet=snippet,
                                custom_description=(
                                    "Unsanitized 'dangerouslySetInnerHTML' usage detected. The content assigned to "
                                    "__html could not be statically verified as sanitized via DOMPurify, creating a "
                                    "direct risk of Cross-Site Scripting (XSS)."
                                ),
                                message="Unsanitized React dangerouslySetInnerHTML usage",
                                explanation=(
                                    "Unsanitized 'dangerouslySetInnerHTML' usage detected. The content assigned to "
                                    "__html could not be statically verified as sanitized via DOMPurify, creating a "
                                    "direct risk of Cross-Site Scripting (XSS)."
                                ),
                                evidence=evidence,
                            )
                        )

        return findings
