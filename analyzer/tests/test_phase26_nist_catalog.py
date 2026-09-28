"""Tests for NIST SP 800-53 Rev 5 compliance catalog and evaluation."""

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


def _make_nist_finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/input_handler.py", line_start=15),
        code_snippet="subprocess.run(user_cmd, shell=True)",
        description="Unsafe input handling or command execution",
        remediation="Validate input syntax and avoid shell=True",
    )


def test_nist_clean_run():
    """Verify NIST SP 800-53 returns COMPLIANT when no findings are detected."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.NIST_SP_800_53_R5])
    res = evaluator.evaluate_framework(ComplianceFramework.NIST_SP_800_53_R5, [])
    assert res.overall_score == 100.0
    assert res.status == ComplianceStatus.COMPLIANT


def test_nist_information_input_validation_si_10():
    """Verify command injection (SEC-PY-003) violates NIST-SI-10 (Information Input Validation)."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.NIST_SP_800_53_R5])
    f = _make_nist_finding("SEC-PY-003")
    res = evaluator.evaluate_framework(ComplianceFramework.NIST_SP_800_53_R5, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "NIST-SI-10")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl.active_violation_count == 1


def test_nist_cryptographic_protection_sc_13():
    """Verify weak cryptographic hash (SEC-PY-006) violates NIST-SC-13."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.NIST_SP_800_53_R5])
    f = _make_nist_finding("SEC-PY-006")
    res = evaluator.evaluate_framework(ComplianceFramework.NIST_SP_800_53_R5, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "NIST-SC-13")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl.active_violation_count == 1


def test_nist_access_enforcement_ac_3():
    """Verify CSRF exemption (SEC-PY-008) violates NIST-AC-3 (Access Enforcement)."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.NIST_SP_800_53_R5])
    f = _make_nist_finding("SEC-PY-008")
    res = evaluator.evaluate_framework(ComplianceFramework.NIST_SP_800_53_R5, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "NIST-AC-3")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
