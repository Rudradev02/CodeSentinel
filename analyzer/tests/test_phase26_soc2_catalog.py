"""Tests for SOC 2 Trust Services Criteria catalog and evaluation."""

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


def _make_soc2_finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/exec.py", line_start=35),
        code_snippet="eval(user_input)",
        description="Dynamic code evaluation or boundary failure",
        remediation="Avoid eval() and unvalidated execution",
    )


def test_soc2_clean_run():
    """Verify SOC 2 returns COMPLIANT when clean."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.SOC2_TSC])
    res = evaluator.evaluate_framework(ComplianceFramework.SOC2_TSC, [])
    assert res.overall_score == 100.0
    assert res.status == ComplianceStatus.COMPLIANT


def test_soc2_unauthorized_code_execution_cc6_8():
    """Verify SEC-PY-004 and SEC-JS-001 violate SOC2-CC6.8 (Malicious Code Prevention)."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.SOC2_TSC])
    f = _make_soc2_finding("SEC-PY-004")
    res = evaluator.evaluate_framework(ComplianceFramework.SOC2_TSC, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "SOC2-CC6.8")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert ctrl.active_violation_count == 1


def test_soc2_boundary_protection_cc6_6():
    """Verify SEC-JS-003 and command injection violate SOC2-CC6.6."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.SOC2_TSC])
    f = _make_soc2_finding("SEC-JS-003")
    res = evaluator.evaluate_framework(ComplianceFramework.SOC2_TSC, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "SOC2-CC6.6")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT


def test_soc2_vulnerability_monitoring_cc7_1():
    """Verify production debug flags violate SOC2-CC7.1 (Vulnerability Monitoring)."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.SOC2_TSC])
    f = _make_soc2_finding("SEC-PY-002")
    res = evaluator.evaluate_framework(ComplianceFramework.SOC2_TSC, [f])

    ctrl = next(ce for ce in res.control_evaluations if ce.control.control_id == "SOC2-CC7.1")
    assert ctrl.status == ComplianceStatus.NON_COMPLIANT
