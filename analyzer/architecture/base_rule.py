"""Abstract base class for architecture anti-pattern rules in CodeSentinel."""

from abc import ABC, abstractmethod
from typing import Any, Optional
import uuid

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    RuleDefinition,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph


class BaseArchitectureRule(ABC):
    """Abstract base class defining an architecture anti-pattern rule.
    
    Architecture rules inspect the dependency graph topology and structural
    metrics to identify anti-patterns (e.g., circular dependencies, god modules).
    """

    rule_id: str
    name: str
    evidence_type: EvidenceType = EvidenceType.DETERMINISTIC
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.HIGH
    description: str
    remediation: str
    languages: list[str] = []
    supported_languages: list[str] = []
    frameworks: list[str] = []
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    rationale: Optional[str] = None

    def get_definition(self) -> RuleDefinition:
        """Returns the formal metadata definition for this rule."""
        return RuleDefinition(
            rule_id=self.rule_id,
            name=self.name,
            category=FindingCategory.ARCHITECTURE,
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
        """Helper to construct a validated Finding instance for this architecture rule."""
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
            category=FindingCategory.ARCHITECTURE,
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
    def analyze(self, graph: ArchitectureGraph) -> list[Finding]:
        """Analyze the architecture dependency graph for structural defects.
        
        Args:
            graph: Fully constructed ArchitectureGraph containing nodes and edges.
            
        Returns:
            List of detected architecture Finding instances.
        """
        pass
