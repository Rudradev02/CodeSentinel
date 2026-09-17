"""Abstract base class for security rules in CodeSentinel."""

from abc import ABC, abstractmethod
from typing import Any, Optional

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    RuleDefinition,
    SourceLocation,
)


class BaseSecurityRule(ABC):
    """Abstract base class defining a security rule contract.
    
    Security rules analyze source code or AST contexts and return
    a list of identified Finding objects.
    """

    rule_id: str
    name: str
    evidence_type: EvidenceType = EvidenceType.DETERMINISTIC
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.HIGH
    languages: list[str] = []
    frameworks: list[str] = []
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    def get_definition(self) -> RuleDefinition:
        """Returns the formal metadata definition for this rule."""
        return RuleDefinition(
            rule_id=self.rule_id,
            name=self.name,
            category=FindingCategory.SECURITY,
            evidence_type=self.evidence_type,
            severity=self.severity,
            confidence=self.confidence,
            description=self.description,
            remediation=self.remediation,
            languages=self.languages,
            frameworks=self.frameworks,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
        )

    def create_finding(
        self,
        location: SourceLocation,
        code_snippet: str,
        custom_description: Optional[str] = None,
        custom_remediation: Optional[str] = None,
        confidence_override: Optional[FindingConfidence] = None,
    ) -> Finding:
        """Helper to construct a validated Finding instance for this rule."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=FindingCategory.SECURITY,
            evidence_type=self.evidence_type,
            severity=self.severity,
            confidence=confidence_override or self.confidence,
            location=location,
            code_snippet=code_snippet,
            description=custom_description or self.description,
            remediation=custom_remediation or self.remediation,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
        )

    @abstractmethod
    def analyze(
        self,
        file_path: str,
        content: str,
        ast_node: Optional[Any] = None,
    ) -> list[Finding]:
        """Analyze a file or its AST representation.
        
        Args:
            file_path: Relative path to the file.
            content: Raw source code content.
            ast_node: Optional pre-parsed AST node (e.g. ast.AST or tree-sitter node).
            
        Returns:
            List of detected Finding instances.
        """
        pass
