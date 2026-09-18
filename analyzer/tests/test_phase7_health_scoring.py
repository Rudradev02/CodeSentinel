"""Unit tests for deterministic Codebase Health Scoring, non-double-counting, and audit logs."""

from analyzer.architecture.health import HealthScoreCalculator, calculate_letter_grade
from analyzer.models.findings import Finding, FindingCategory, FindingSeverity, FindingConfidence, EvidenceType, SourceLocation


def _make_dummy_finding(rule_id: str, severity: FindingSeverity, category: FindingCategory) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=category,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        evidence_type=EvidenceType.DETERMINISTIC,
        location=SourceLocation(file_path="app/test.py", line_start=1),
        code_snippet="x = 1",
        description="test description",
        remediation="test remediation",
    )


def test_clean_health_score():
    health = HealthScoreCalculator.compute(security_findings=[], architecture_findings=[])
    assert health.overall_score == 100.0
    assert health.overall_grade == "A"
    assert health.architecture_health.score == 100.0
    assert health.architecture_health.grade == "A"
    assert len(health.architecture_health.deductions) == 0
    assert health.security_posture.score == 100.0
    assert health.security_posture.grade == "A"
    assert len(health.security_posture.deductions) == 0
    assert health.total_deductions_count == 0


def test_deduction_reconstructibility():
    """Verify 100 - sum(points_deducted) == sub_score exactly."""
    f1 = _make_dummy_finding("SEC-PY-001", FindingSeverity.CRITICAL, FindingCategory.SECURITY)
    f2 = _make_dummy_finding("SEC-PY-002", FindingSeverity.HIGH, FindingCategory.SECURITY)
    f3 = _make_dummy_finding("ARC-001", FindingSeverity.HIGH, FindingCategory.ARCHITECTURE)
    f4 = _make_dummy_finding("ARC-005", FindingSeverity.MEDIUM, FindingCategory.ARCHITECTURE)

    health = HealthScoreCalculator.compute(
        security_findings=[f1, f2],
        architecture_findings=[f3, f4],
    )

    # Security: 1 CRITICAL (-25), 1 HIGH (-15) = 40.0 deducted => 60.0
    sec_deductions = sum(d.points_deducted for d in health.security_posture.deductions)
    assert sec_deductions == 40.0
    assert health.security_posture.score == round(100.0 - sec_deductions, 2)
    assert health.security_posture.grade == "D"

    # Architecture: 1 HIGH (-15), 1 MEDIUM (-5) = 20.0 deducted => 80.0
    arch_deductions = sum(d.points_deducted for d in health.architecture_health.deductions)
    assert arch_deductions == 20.0
    assert health.architecture_health.score == round(100.0 - arch_deductions, 2)
    assert health.architecture_health.grade == "B"

    # Overall: 0.55 * 60.0 + 0.45 * 80.0 = 33.0 + 36.0 = 69.0 (Grade D)
    expected_overall = round(0.55 * 60.0 + 0.45 * 80.0, 2)
    assert health.overall_score == expected_overall
    assert health.overall_grade == "D"


def test_rule_capping():
    """Verify point deductions are capped per rule to prevent unbounded degradation from one smell type."""
    # 10 HIGH findings of same rule SEC-PY-001 (10 * 15 = 150 points, capped at 45.0 points)
    many_findings = [_make_dummy_finding("SEC-PY-001", FindingSeverity.HIGH, FindingCategory.SECURITY) for _ in range(10)]
    sub = HealthScoreCalculator.calculate_sub_score(many_findings, category="SECURITY")
    
    total_deducted = sum(d.points_deducted for d in sub.deductions)
    assert total_deducted <= 45.0
    assert sub.score >= 55.0


def test_score_clamping_to_zero():
    """Verify massive findings clamp at 0.0, never negative."""
    lots_of_criticals = [
        _make_dummy_finding(f"SEC-PY-{i:03d}", FindingSeverity.CRITICAL, FindingCategory.SECURITY)
        for i in range(20)
    ]
    sub = HealthScoreCalculator.calculate_sub_score(lots_of_criticals, category="SECURITY")
    assert sub.score == 0.0
    assert sub.grade == "F"


def test_letter_grade_boundaries():
    assert calculate_letter_grade(100.0) == "A"
    assert calculate_letter_grade(90.0) == "A"
    assert calculate_letter_grade(89.99) == "B"
    assert calculate_letter_grade(80.0) == "B"
    assert calculate_letter_grade(79.99) == "C"
    assert calculate_letter_grade(70.0) == "C"
    assert calculate_letter_grade(69.99) == "D"
    assert calculate_letter_grade(60.0) == "D"
    assert calculate_letter_grade(59.99) == "F"
    assert calculate_letter_grade(0.0) == "F"
