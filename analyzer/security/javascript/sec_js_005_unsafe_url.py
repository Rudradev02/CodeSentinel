"""SEC-JS-005: Unsafe URL Protocol Handling (javascript:)."""

import re
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

JAVASCRIPT_PROTOCOL_PREFIX = re.compile(r"^\s*javascript:\s*", re.IGNORECASE)


class RuleSecJs005(BaseSecurityRule):
    """SEC-JS-005: Unsafe URL Protocol Handling (javascript:)."""

    rule_id = "SEC-JS-005"
    name = "Unsafe URL Protocol Handling (javascript:)"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react"]
    description = (
        "Detected explicit or statically constructed 'javascript:' pseudo-protocol URL in href or src attribute. "
        "Executing javascript: URLs triggers arbitrary script execution in the context of the user session."
    )
    rationale = (
        "Rendering user-influenced or hardcoded 'javascript:' URLs in DOM attributes allows script execution "
        "in the document origin when triggered by user interaction or browser navigation."
    )
    remediation = (
        "Enforce explicit protocol validation allowing only trusted URL schemes (e.g. 'https:', 'http:', 'mailto:'). "
        "Never allow links or resource locators with 'javascript:' schemes."
    )
    cwe_id = "CWE-79"
    owasp_category = "A03:2021-Injection"

    def _is_dangerous_protocol(self, val_node: Node, source_bytes: bytes) -> bool:
        """Statically establish whether the node explicitly uses or constructs a javascript: protocol."""
        # Case 1: String literal, e.g. href="javascript:alert(1)" or href={'javascript:alert(1)'}
        if val_node.type == "string":
            raw_text = node_text(val_node, source_bytes).strip("'\"")
            return bool(JAVASCRIPT_PROTOCOL_PREFIX.search(raw_text))

        # Case 2: Template string, e.g. href={`javascript:${code}`}
        if val_node.type == "template_string":
            raw_text = node_text(val_node, source_bytes).strip("`")
            return bool(JAVASCRIPT_PROTOCOL_PREFIX.search(raw_text))

        # Case 3: Binary expression concatenation, e.g. href={'javascript:' + payload}
        if val_node.type == "binary_expression":
            left_child = val_node.child_by_field_name("left")
            if left_child and left_child.type == "string":
                left_text = node_text(left_child, source_bytes).strip("'\"")
                return bool(JAVASCRIPT_PROTOCOL_PREFIX.search(left_text))

        # Generic dynamic variables (e.g. href={url}, href={userProvidedUrl}) are NOT flagged per Phase 3 rules
        return False

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
            if node.type == "jsx_attribute":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    for child in node.children:
                        if child.type in ("property_identifier", "jsx_identifier", "identifier"):
                            name_node = child
                            break

                if name_node and node_text(name_node, source_bytes) in ("href", "src"):
                    value_node = node.child_by_field_name("value")
                    if value_node is None:
                        for child in node.children:
                            if child.type in ("string", "jsx_expression"):
                                value_node = child
                                break

                    if value_node:
                        # Extract inner expression if inside jsx_expression { ... }
                        check_target = value_node
                        if value_node.type == "jsx_expression":
                            for child in value_node.children:
                                if child.type not in ("{", "}"):
                                    check_target = child
                                    break

                        if self._is_dangerous_protocol(check_target, source_bytes):
                            line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                            attr_name = node_text(name_node, source_bytes)
                            snippet = (
                                lines[line_start - 1].strip()
                                if 0 <= line_start - 1 < len(lines)
                                else f'{attr_name}="javascript:..."'
                            )
                            location = SourceLocation(
                                file_path=norm_path,
                                line_start=line_start,
                                line_end=line_end,
                                col_start=col_start,
                                col_end=col_end,
                            )
                            evidence = {
                                "attribute": attr_name,
                                "protocol": "javascript:",
                            }
                            findings.append(
                                self.create_finding(
                                    location=location,
                                    code_snippet=snippet,
                                    custom_description=(
                                        f"Dangerous 'javascript:' URL pseudo-protocol detected in '{attr_name}'. "
                                        "Navigating to or loading resources from javascript: URLs executes arbitrary scripts in the client context (XSS)."
                                    ),
                                    message=f"Unsafe 'javascript:' URL scheme in '{attr_name}' attribute",
                                    explanation=(
                                        f"Dangerous 'javascript:' URL pseudo-protocol detected in '{attr_name}' attribute. "
                                        "Navigating to or loading resources from javascript: URLs executes arbitrary scripts in the client context (XSS)."
                                    ),
                                    evidence=evidence,
                                )
                            )

        return findings
