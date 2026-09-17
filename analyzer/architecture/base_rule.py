"""Abstract base class for architecture anti-pattern rules in CodeSentinel."""

from abc import ABC, abstractmethod
from typing import Optional

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
        )

    def create_finding(
        self,
        location: SourceLocation,
        code_snippet: str,
        custom_description: Optional[str] = None,
        custom_remediation: Optional[str] = None,
        confidence_override: Optional[FindingConfidence] = None,
    ) -> Finding:
        """Helper to construct a validated Finding instance for this architecture rule."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=FindingCategory.ARCHITECTURE,
            evidence_type=self.evidence_type,
            severity=self.severity,
            confidence=confidence_override or self.confidence,
            location=location,
            code_snippet=code_snippet,
            description=custom_description or self.description,
            remediation=custom_remediation or self.remediation,
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
