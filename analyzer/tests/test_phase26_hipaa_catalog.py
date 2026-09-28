"""Tests for HIPAA Security Rule compliance catalog and evaluation."""

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


def _make_finding(rule_id: str, policy_id: str = "") -> Finding:
    evidence = {}
    if policy_id:
        evidence["policy_id"] = policy_id
    return Finding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/auth.py", line_start=20),
        code_snippet="def unauthenticated_api(): pass",
        description="Disabled authentication or integrity risk",
        remediation="Enforce authentication decorator",
        evidence=evidence,
    )


def test_hipaa_clean_run():
    """Verify HIPAA returns COMPLIANT when no findings are detected."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.HIPAA_SECURITY])
    res = evaluator.evaluate_framework(ComplianceFramework.HIPAA_SECURITY, [])
    assert res.overall_score == 100.0
    assert res.status == ComplianceStatus.COMPLIANT


def test_hipaa_access_control_violation():
    """Verify SEC-PY-008 violates HIPAA-164.312(a)(1) Access Control."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.HIPAA_SECURITY])
    f = _make_finding("SEC-PY-008", policy_id="POL-AUTHZ-01")
    res = evaluator.evaluate_framework(ComplianceFramework.HIPAA_SECURITY, [f])

    assert res.status == ComplianceStatus.NON_COMPLIANT
    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "HIPAA-164.312(a)(1)")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl.active_violation_count == 1


def test_hipaa_transmission_security_violation():
    """Verify CORS wildcard (SEC-PY-007) violates HIPAA-164.312(e)(1) Transmission Security."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.HIPAA_SECURITY])
    f = _make_finding("SEC-PY-007")
    res = evaluator.evaluate_framework(ComplianceFramework.HIPAA_SECURITY, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "HIPAA-164.312(e)(1)")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl.active_violation_count == 1


def test_hipaa_data_integrity_violation():
    """Verify raw SQL injection violates HIPAA-164.312(c)(1) Data Integrity."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.HIPAA_SECURITY])
    f = _make_finding("SEC-PY-005")
    res = evaluator.evaluate_framework(ComplianceFramework.HIPAA_SECURITY, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "HIPAA-164.312(c)(1)")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
