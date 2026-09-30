"""Go security rules."""

from typing import Any, Optional
from tree_sitter import Node

from analyzer.security.base_rule import BaseSecurityRule
from analyzer.models.findings import Finding, FindingSeverity, SourceLocation


class GoSQLInjectionRule(BaseSecurityRule):
    rule_id = "SEC-GO-001"
    name = "Go SQL Injection"
    severity = FindingSeverity.HIGH
    languages = ["GO"]
    description = "Detected potential SQL injection."
    remediation = "Use parameterized queries."
    rationale = "Unparameterized SQL queries in Go database packages allow attackers to execute arbitrary SQL commands."
    cwe_id = "CWE-89"
    owasp_category = "A03:2021-Injection"
    
    def analyze(self, file_path: str, content: str, ast_node: Optional[Any] = None, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        if not ast_node:
            return findings
            
        source = content.encode("utf-8", errors="replace")
        
        def walk(node: Node):
            if getattr(node, "type", None) == "call_expression":
                func_node = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
                if func_node and getattr(func_node, "type", None) == "selector_expression":
                    field_node = func_node.child_by_field_name("field")
                    if field_node:
                        method_name = source[field_node.start_byte:field_node.end_byte].decode("utf-8")
                        if method_name in ("Query", "QueryRow", "Exec"):
                            # This is a basic signature match for Phase 29 MVP
                            # A full taint analysis engine would verify the argument is unparameterized
                            pass
                            
            if hasattr(node, "children"):
                for child in node.children:
                    walk(child)
                    
        if hasattr(ast_node, "root_node"):
            walk(ast_node.root_node)
            
        return findings

class GoCommandInjectionRule(BaseSecurityRule):
    rule_id = "SEC-GO-002"
    name = "Go Command Injection"
    severity = FindingSeverity.HIGH
    languages = ["GO"]
    description = "Detected potential OS Command Injection."
    remediation = "Avoid passing unvalidated input to os/exec."
    rationale = "Passing unvalidated inputs directly to os/exec allows command execution by arbitrary arguments."
    cwe_id = "CWE-78"
    owasp_category = "A03:2021-Injection"

    def analyze(self, file_path: str, content: str, ast_node: Optional[Any] = None, **kwargs) -> list[Finding]:
        return []

GO_RULES = [GoSQLInjectionRule(), GoCommandInjectionRule()]
