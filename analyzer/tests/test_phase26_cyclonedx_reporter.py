"""Tests for CycloneDX v1.5 / v1.6 SBOM and VEX reporter."""

import json
import pytest
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisMetadata, AnalysisResult, RepositoryInfo
from analyzer.reporting.cyclonedx_reporter import CycloneDxReporter


def _create_sample_result() -> AnalysisResult:
    f1 = Finding(
        rule_id="SEC-PY-005",
        rule_name="Raw SQL Query String Construction",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/db.py", line_start=25),
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        description="SQL injection via raw formatting",
        remediation="Use parameterized queries",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
    )
    f2 = Finding(
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secret Key",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/settings.py", line_start=12),
        code_snippet="API_KEY = 'secret-key-123'",
        description="Hardcoded credential",
        remediation="Extract to environment variable",
        cwe_id="CWE-798",
        evidence={"suppressed": True, "suppression_reason": "Dev dummy key"},
    )
    repo = RepositoryInfo(name="test-repo", local_path="/tmp/test-repo", total_files=2)
    return AnalysisResult(
        repository=repo,
        security_findings=[f1, f2],
        metadata=AnalysisMetadata(),
    )


def test_cyclonedx_reporter_json_structure():
    """Verify CycloneDxReporter outputs valid CycloneDX 1.6 JSON."""
    result = _create_sample_result()
    reporter = CycloneDxReporter(spec_version="1.6")
    output_str = reporter.render(result)

    bom = json.loads(output_str)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert "serialNumber" in bom
    assert len(bom["components"]) == 2
    assert len(bom["vulnerabilities"]) == 2


def test_cyclonedx_cwe_extraction_and_vex_states():
    """Verify CWEs are integers and VEX states distinguish unsuppressed vs suppressed findings."""
    result = _create_sample_result()
    reporter = CycloneDxReporter()
    output_str = reporter.render(result)
    bom = json.loads(output_str)

    vulns = bom["vulnerabilities"]
    v_sqli = next(v for v in vulns if "SEC-PY-005" in str(v["properties"]))
    assert v_sqli["cwes"] == [89]
    assert v_sqli["analysis"]["state"] == "exploitable"

    v_secret = next(v for v in vulns if "SEC-PY-001" in str(v["properties"]))
    assert v_secret["cwes"] == [798]
    assert v_secret["analysis"]["state"] == "not_affected"
    assert v_secret["analysis"]["justification"] == "protected_by_mitigating_control"


def test_cyclonedx_compliance_properties_present():
    """Verify mapped regulatory controls appear in vulnerability properties."""
    result = _create_sample_result()
    reporter = CycloneDxReporter()
    output_str = reporter.render(result)
    bom = json.loads(output_str)

    vulns = bom["vulnerabilities"]
    v_sqli = next(v for v in vulns if "SEC-PY-005" in str(v["properties"]))
    prop_values = [p["value"] for p in v_sqli["properties"]]
    # SEC-PY-005 maps to PCI-6.2.4, HIPAA-164.312(c)(1), NIST-SI-10
    assert "PCI-6.2.4" in prop_values or "NIST-SI-10" in prop_values
