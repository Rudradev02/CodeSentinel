"""SEC-JS-004: Hardcoded Client-Side Secrets."""

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
from analyzer.rules.entropy import calculate_shannon_entropy, is_likely_secret_string, redact_secret
from analyzer.rules.js_ast_helper import (
    get_node_line_and_col,
    node_text,
    parse_js_ts_source,
    traverse_nodes,
)
from analyzer.security.base_rule import BaseSecurityRule

JS_SECRET_NAME_PATTERN = re.compile(
    r"(?i)(^|_)(client_?secret|stripe_?secret|secret_?key|private_?key|api_?secret|auth_?secret|jwt_?secret|api_?key|aws_secret)($|_)"
)


class RuleSecJs004(BaseSecurityRule):
    """SEC-JS-004: Hardcoded Client-Side Secrets."""

    rule_id = "SEC-JS-004"
    name = "Hardcoded Client-Side Secrets"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["general", "react"]
    description = (
        "Detected variable declaration containing a hardcoded secret in client-side code. "
        "Any credentials compiled into frontend client bundles are publicly readable by end users."
    )
    rationale = (
        "Client bundles are shipped to browsers as plaintext JavaScript, exposing any embedded API secrets, "
        "tokens, or private keys to inspection and unauthorized extraction."
    )
    remediation = (
        "Never bundle private secrets into frontend code. Store secrets on the backend and "
        "access protected APIs via server-side proxies or session-authenticated endpoints."
    )
    cwe_id = "CWE-798"
    owasp_category = "A07:2021-Identification and Authentication Failures"

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
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")

                if name_node and value_node and name_node.type == "identifier":
                    var_name = node_text(name_node, source_bytes)
                    if JS_SECRET_NAME_PATTERN.search(var_name):
                        # Value must be a string literal or simple template string
                        if value_node.type in ("string", "template_string"):
                            raw_val = node_text(value_node, source_bytes).strip("'\"`")
                            if is_likely_secret_string(raw_val):
                                line_start, line_end, col_start, col_end = get_node_line_and_col(node)
                                raw_snippet = (
                                    lines[line_start - 1].strip()
                                    if 0 <= line_start - 1 < len(lines)
                                    else f"const {var_name} = '...'"
                                )
                                redacted_val = redact_secret(raw_val)
                                safe_snippet = raw_snippet.replace(raw_val, redacted_val)
                                entropy = calculate_shannon_entropy(raw_val)
                                location = SourceLocation(
                                    file_path=norm_path,
                                    line_start=line_start,
                                    line_end=line_end,
                                    col_start=col_start,
                                    col_end=col_end,
                                )
                                evidence = {
                                    "variable_name": var_name,
                                    "entropy": round(entropy, 2),
                                    "secret_preview": redacted_val,
                                }
                                findings.append(
                                    self.create_finding(
                                        location=location,
                                        code_snippet=safe_snippet,
                                        custom_description=(
                                            f"Hardcoded secret detected in client variable '{var_name}' "
                                            f"(entropy: {entropy:.2f} bits/char). Embedding credentials in frontend "
                                            "code compromises them immediately upon deployment to browsers."
                                        ),
                                        message=f"Hardcoded secret detected in client variable '{var_name}'",
                                        explanation=(
                                            f"Hardcoded secret detected in client variable '{var_name}' (entropy: {entropy:.2f} bits/char). "
                                            "Embedding credentials in frontend code compromises them immediately upon deployment to browsers."
                                        ),
                                        evidence=evidence,
                                    )
                                )

        return findings
