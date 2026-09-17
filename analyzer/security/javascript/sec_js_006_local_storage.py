"""SEC-JS-006: Sensitive Data Stored in LocalStorage."""

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

SENSITIVE_STORAGE_KEY_PATTERN = re.compile(
    r"(?i)(token|jwt|auth|password|secret|access_token|refresh_token|credential|api_key)"
)


class RuleSecJs006(BaseSecurityRule):
    """SEC-JS-006: Sensitive Data Stored in LocalStorage."""

    rule_id = "SEC-JS-006"
    name = "Sensitive Data Stored in LocalStorage"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.MEDIUM
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react"]
    description = (
        "Detected sensitive token or credential stored in localStorage or sessionStorage. "
        "Browser Web Storage is accessible to any JavaScript running on the origin and cannot be "
        "protected with HttpOnly flags, making stored tokens vulnerable to exfiltration via XSS."
    )
    rationale = (
        "Web Storage (localStorage and sessionStorage) lacks cookie-based security flags like HttpOnly, "
        "making stored authentication credentials accessible to any script running within the browser origin."
    )
    remediation = (
        "Store authentication tokens and session identifiers in HttpOnly, Secure, SameSite=Strict cookies "
        "rather than localStorage/sessionStorage. Use Web Storage only for non-sensitive UI state."
    )
    cwe_id = "CWE-922"
    owasp_category = "A04:2021-Insecure Design"

    def _is_storage_set_item(self, func_node: Node, source_bytes: bytes) -> tuple[bool, str]:
        """Check if call is localStorage.setItem or sessionStorage.setItem."""
        if func_node.type != "member_expression":
            return False, ""

        prop_node = func_node.child_by_field_name("property")
        if prop_node is None or node_text(prop_node, source_bytes) != "setItem":
            return False, ""

        obj_node = func_node.child_by_field_name("object")
        if obj_node is None:
            return False, ""

        obj_text = node_text(obj_node, source_bytes)
        if obj_text in ("localStorage", "sessionStorage", "window.localStorage", "window.sessionStorage"):
            return True, obj_text.split(".")[-1]

        return False, ""

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

                if func_node:
                    is_storage, storage_type = self._is_storage_set_item(func_node, source_bytes)
                    if is_storage:
                        args_node = node.child_by_field_name("arguments")
                        if args_node and len(args_node.children) >= 2:
                            # In tree-sitter arguments: '(' is child 0, first arg is child 1
                            first_arg = None
                            for child in args_node.children:
                                if child.type not in ("(", ")", ","):
                                    first_arg = child
                                    break

                            if first_arg and first_arg.type in ("string", "template_string"):
                                key_str = node_text(first_arg, source_bytes).strip("'\"`")
                                if SENSITIVE_STORAGE_KEY_PATTERN.search(key_str):
                                    line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                                    snippet = (
                                        lines[line_start - 1].strip()
                                        if 0 <= line_start - 1 < len(lines)
                                        else f"{storage_type}.setItem('{key_str}', ...)"
                                    )
                                    location = SourceLocation(
                                        file_path=norm_path,
                                        line_start=line_start,
                                        line_end=line_end,
                                        col_start=col_start,
                                        col_end=col_end,
                                    )
                                    evidence = {
                                        "storage": storage_type,
                                        "key": key_str,
                                    }
                                    findings.append(
                                        self.create_finding(
                                            location=location,
                                            code_snippet=snippet,
                                            custom_description=(
                                                f"Sensitive credential key '{key_str}' written to {storage_type}. "
                                                "Data stored in Web Storage is vulnerable to theft via Cross-Site Scripting (XSS)."
                                            ),
                                            message=f"Sensitive credential key '{key_str}' stored in {storage_type}",
                                            explanation=(
                                                f"Sensitive credential key '{key_str}' written to {storage_type}. "
                                                "Data stored in Web Storage is accessible to any script in the origin and vulnerable to theft via Cross-Site Scripting (XSS)."
                                            ),
                                            evidence=evidence,
                                        )
                                    )

        return findings
