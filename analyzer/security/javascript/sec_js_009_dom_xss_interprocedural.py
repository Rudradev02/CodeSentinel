"""SEC-JS-009: Interprocedural DOM XSS."""

import hashlib
from typing import Any, Optional
import uuid

from analyzer.dataflow.callgraph.models import InterproceduralTaintPath
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    RuleCategory,
    SourceLocation,
)
from analyzer.security.base_rule import BaseSecurityRule


class RuleSecJs009(BaseSecurityRule):
    """SEC-JS-009: Interprocedural DOM XSS."""

    rule_id = "SEC-JS-009"
    name = "Interprocedural DOM XSS"
    category = RuleCategory.SECURITY
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["javascript", "typescript"]
    frameworks = ["react", "general"]
    target_sink_category = SinkCategory.DOM_INJECTION
    description = (
        "Untrusted input propagates across function call boundaries into a DOM manipulation sink (e.g. innerHTML) "
        "without sanitization."
    )
    rationale = (
        "Passing raw user input across function boundaries into DOM insertion sinks allows cross-site scripting (XSS), "
        "enabling cookie theft, credential harvesting, and session hijacking in user browsers."
    )
    remediation = (
        "Sanitize HTML strings with DOMPurify before assigning to innerHTML, or pass textContent "
        "instead of raw HTML strings across functions."
    )
    cwe_id = "CWE-79"
    owasp_category = "A03:2021-Injection"

    def analyze(
        self,
        file_path: str,
        content: str,
        ast_node: Optional[Any] = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Generate findings for interprocedural paths terminating at sinks in file_path."""
        interprocedural_paths: Optional[list[InterproceduralTaintPath]] = kwargs.get("interprocedural_paths")
        if not interprocedural_paths:
            return []

        norm_path = file_path.replace("\\", "/")
        lines = content.splitlines()
        findings: list[Finding] = []

        for path in interprocedural_paths:
            if path.category != self.target_sink_category:
                continue
            sink_file = path.sink.get("file_path", "").replace("\\", "/")
            if sink_file != norm_path:
                continue

            findings.append(self.create_finding_from_path(path, lines, norm_path))

        return findings

    def create_finding_from_path(
        self,
        path: InterproceduralTaintPath,
        lines: Optional[list[str]] = None,
        norm_path: Optional[str] = None,
    ) -> Finding:
        """Create a Finding from an InterproceduralTaintPath."""
        sink_file = norm_path or path.sink.get("file_path", "").replace("\\", "/")
        sink_line = path.sink.get("line", 1)
        sink_col = path.sink.get("column", 0)
        source_file = path.source.get("file_path", "").replace("\\", "/")
        source_line = path.source.get("line", 1)

        call_chain_str = "->".join(f"{s.caller_function}:{s.call_site_line}->{s.callee_function}" for s in path.call_chain)
        call_chain_hash = hashlib.sha256(call_chain_str.encode("utf-8")).hexdigest()[:16]
        finding_seed = f"{self.rule_id}:{source_file}:{source_line}:{sink_file}:{sink_line}:{call_chain_hash}"
        deterministic_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, finding_seed))

        snippet = path.sink.get("expression", "")
        if lines and 0 < sink_line <= len(lines):
            snippet = lines[sink_line - 1].strip()

        location = SourceLocation(
            file_path=sink_file,
            line_start=sink_line,
            line_end=sink_line,
            col_start=sink_col,
            col_end=sink_col + len(snippet),
        )

        msg = f"{self.name}: {path.path_summary}"
        return Finding(
            id=deterministic_id,
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            confidence=self.confidence,
            location=location,
            code_snippet=snippet,
            message=msg,
            description=msg,
            rationale=self.rationale,
            remediation=self.remediation,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            evidence_type=self.evidence_type,
            evidence=path.model_dump(),
        )
