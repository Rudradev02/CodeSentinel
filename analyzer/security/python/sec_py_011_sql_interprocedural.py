"""SEC-PY-011: Interprocedural SQL Injection."""

import hashlib
from typing import Any, Optional
import uuid

from analyzer.dataflow.callgraph.models import InterproceduralTaintPath
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.security.base_rule import BaseSecurityRule


class RuleSecPy011(BaseSecurityRule):
    """SEC-PY-011: Interprocedural SQL Injection."""

    rule_id = "SEC-PY-011"
    name = "Interprocedural SQL Injection"
    category = FindingCategory.SECURITY
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["flask", "django", "general"]
    target_sink_category = SinkCategory.SQL_EXECUTE
    description = (
        "Untrusted user input propagates across function call boundaries into a database query execution sink "
        "without parameterized query binding or context-specific numeric validation."
    )
    rationale = (
        "Constructing dynamic SQL queries using values passed across function call boundaries allows untrusted input "
        "to alter SQL syntax, enabling unauthorized data exfiltration, database alteration, and privilege escalation."
    )
    remediation = (
        "Use parameterized query placeholders (e.g. cursor.execute('SELECT * FROM t WHERE id = %s', (id,))) "
        "or an ORM across function boundaries rather than passing dynamically concatenated query strings."
    )
    cwe_id = "CWE-89"
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

        snippet = (
            lines[sink_line - 1].strip()
            if lines and 0 < sink_line <= len(lines) and lines[sink_line - 1].strip()
            else (path.sink.get("expression") or f"{self.name} at {sink_file}:{sink_line}")
        )

        location = SourceLocation(
            file_path=sink_file,
            line_start=sink_line,
            line_end=sink_line,
            col_start=sink_col,
            col_end=sink_col + len(snippet),
        )

        msg = f"{self.name}: {path.path_summary}"
        finding = self.create_finding(
            location=location,
            code_snippet=snippet,
            custom_description=msg,
            message=msg,
            evidence=path.model_dump(),
        )
        finding.id = deterministic_id
        return finding
