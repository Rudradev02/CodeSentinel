"""Abstract base class for security rules in CodeSentinel."""

from abc import ABC, abstractmethod
import uuid
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

    rationale: Optional[str] = None
    supported_languages: list[str] = []

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
            rationale=self.rationale,
            supported_languages=self.supported_languages or self.languages,
        )

    def create_finding(
        self,
        location: SourceLocation,
        code_snippet: str,
        custom_description: Optional[str] = None,
        custom_remediation: Optional[str] = None,
        confidence_override: Optional[FindingConfidence] = None,
        message: Optional[str] = None,
        explanation: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> Finding:
        """Helper to construct a validated Finding instance for this rule."""
        col = location.col_start if location.col_start is not None else 0
        finding_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"{self.rule_id}:{location.file_path}:{location.line_start}:{col}",
            )
        )
        desc = custom_description or self.description
        expl = explanation or desc
        msg = message or self.name
        ev = evidence if evidence is not None else {}
        return Finding(
            id=finding_id,
            rule_id=self.rule_id,
            rule_name=self.name,
            category=FindingCategory.SECURITY,
            evidence_type=self.evidence_type,
            severity=self.severity,
            confidence=confidence_override or self.confidence,
            location=location,
            code_snippet=code_snippet,
            description=desc,
            remediation=custom_remediation or self.remediation,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            created_at=None,
            message=msg,
            explanation=expl,
            evidence=ev,
            file=location.file_path,
            title=self.name,
        )

    @abstractmethod
    def analyze(
        self,
        file_path: str,
        content: str,
        ast_node: Optional[Any] = None,
        **kwargs: Any,
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
