"""Tests for PCI-DSS v4.0 compliance evaluation and control verification."""

import pytest
from analyzer.compliance.evaluator import ComplianceEvaluator
from analyzer.compliance.models import ComplianceFramework, ComplianceStatus
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)


def _make_dummy_finding(rule_id: str, severity: FindingSeverity = FindingSeverity.HIGH, is_suppressed: bool = False) -> Finding:
    evidence = {}
    if is_suppressed:
        evidence["suppressed"] = True
        evidence["suppression_reason"] = "Authorized deviation"

    return Finding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/views.py", line_start=10),
        code_snippet="cursor.execute(sql)",
        description="SQL injection vulnerability detected",
        remediation="Use parameterized queries",
        evidence=evidence,
    )


def test_pci_dss_clean_run_is_compliant():
    """Verify PCI-DSS v4.0 returns 100% COMPLIANT when no findings are detected."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    res = evaluator.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [])
    assert res.overall_score == 100.0
    assert res.status == ComplianceStatus.COMPLIANT
    assert res.non_compliant_controls == 0
    assert res.unresolved_violations_count == 0


def test_pci_dss_sqli_violation_triggers_non_compliant():
    """Verify an active SQL injection finding triggers NON_COMPLIANT for PCI-6.2.4."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    finding = _make_dummy_finding("SEC-PY-005", severity=FindingSeverity.HIGH)
    res = evaluator.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [finding])

    assert res.status == ComplianceStatus.NON_COMPLIANT
    assert res.unresolved_violations_count == 1

    ctrl_624 = next(ce for ce in res.control_evaluations if ce.control.control_id == "PCI-6.2.4")
    assert ctrl_624.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl_624.active_violation_count == 1
    assert len(ctrl_624.remediation_actions) > 0


def test_pci_dss_suppression_transitions_to_partial_compliance():
    """Verify a suppressed violation results in PARTIALLY_COMPLIANT with logged exception."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    suppressed_finding = _make_dummy_finding("SEC-PY-005", severity=FindingSeverity.HIGH, is_suppressed=True)
    res = evaluator.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [suppressed_finding])

    assert res.status in (ComplianceStatus.PARTIALLY_COMPLIANT, ComplianceStatus.PARTIAL)
    assert res.unresolved_violations_count == 0
    assert res.suppressed_exceptions_count == 1

    ctrl_624 = next(ce for ce in res.control_evaluations if ce.control.control_id == "PCI-6.2.4")
    assert ctrl_624.status in (ComplianceStatus.PARTIALLY_COMPLIANT, ComplianceStatus.PARTIAL)
    assert ctrl_624.compliance_score == 0.8


def test_pci_dss_hardcoded_secrets_violates_req_3_4():
    """Verify SEC-PY-001 violates PCI-3.4 (render PAN unreadable / secret protection)."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    secret_finding = _make_dummy_finding("SEC-PY-001", severity=FindingSeverity.HIGH)
    res = evaluator.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [secret_finding])

    ctrl_34 = next(ce for ce in res.control_evaluations if ce.control.control_id == "PCI-3.4")
    assert ctrl_34.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl_34.active_violation_count == 1
