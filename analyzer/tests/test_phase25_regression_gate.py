"""Phase 25 tests — Regression gate policy evaluation and verdict."""

import pytest

from analyzer.comparison.gate import (
    GateVerdict,
    RegressionGatePolicy,
    RegressionGateResult,
    evaluate_regression_gate,
)
from analyzer.comparison.regression import RegressionClassification, RegressionCause, RegressionSeverity
from analyzer.models.comparison import (
    DifferentialFinding,
    FindingTransition,
    FindingLifecycleState,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence
from analyzer.models.suppression import FindingSuppression, SuppressionKind, SuppressionScope


def _make_finding(severity=FindingSeverity.HIGH, rule_id="SEC-PY-005"):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="src/db.py", line_start=10),
        code_snippet="cursor.execute(query)",
        description="SQL injection",
        remediation="Use parameterized queries",
    )


def _make_diff_finding(severity=FindingSeverity.HIGH, lifecycle_state=None, regression=None, suppression=None):
    return DifferentialFinding(
        finding=_make_finding(severity=severity),
        transition=FindingTransition.NEW,
        lifecycle_state=lifecycle_state,
        regression=regression,
        suppression=suppression,
    )


class TestRegressionGate:
    """Test CI/CD regression gate evaluation."""

    def test_gate_fails_on_critical_regression(self):
        """New CRITICAL finding → FAIL verdict."""
        findings = [_make_diff_finding(severity=FindingSeverity.CRITICAL)]
        result = evaluate_regression_gate(findings)
        assert result.verdict == GateVerdict.FAIL
        assert result.total_blocking == 1

    def test_gate_fails_on_high_regression(self):
        """New HIGH finding → FAIL verdict (default policy)."""
        findings = [_make_diff_finding(severity=FindingSeverity.HIGH)]
        result = evaluate_regression_gate(findings)
        assert result.verdict == GateVerdict.FAIL

    def test_gate_warns_on_medium(self):
        """New MEDIUM finding with default policy (fail_on_new_medium=False) → WARN."""
        findings = [_make_diff_finding(severity=FindingSeverity.MEDIUM)]
        result = evaluate_regression_gate(findings)
        assert result.verdict == GateVerdict.WARN

    def test_gate_passes_with_no_findings(self):
        """Empty findings list → PASS."""
        result = evaluate_regression_gate([])
        assert result.verdict == GateVerdict.PASS
        assert result.total_new == 0

    def test_gate_passes_on_policy_induced(self):
        """POLICY_INDUCED_NEW finding with ignore_policy_induced → PASS."""
        findings = [
            _make_diff_finding(
                severity=FindingSeverity.CRITICAL,
                lifecycle_state=FindingLifecycleState.POLICY_INDUCED_NEW,
            )
        ]
        policy = RegressionGatePolicy(ignore_policy_induced=True)
        result = evaluate_regression_gate(findings, policy)
        assert result.verdict == GateVerdict.PASS
        assert len(result.ignored_findings) == 1

    def test_gate_respects_suppression(self):
        """Suppressed CRITICAL finding → PASS when ignore_suppressed=True."""
        suppression = FindingSuppression(
            suppression_id="SUP-001",
            kind=SuppressionKind.INLINE_ANNOTATION,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
        )
        findings = [_make_diff_finding(severity=FindingSeverity.CRITICAL, suppression=suppression)]
        policy = RegressionGatePolicy(ignore_suppressed=True)
        result = evaluate_regression_gate(findings, policy)
        assert result.verdict == GateVerdict.PASS
        assert len(result.suppressed_findings) == 1

    def test_gate_ignores_pre_existing(self):
        """PRE_EXISTING finding with ignore_pre_existing → PASS."""
        regression = RegressionClassification(
            cause=RegressionCause.PRE_EXISTING,
            severity=RegressionSeverity.ADVISORY,
        )
        findings = [_make_diff_finding(severity=FindingSeverity.HIGH, regression=regression)]
        policy = RegressionGatePolicy(ignore_pre_existing=True)
        result = evaluate_regression_gate(findings, policy)
        assert result.verdict == GateVerdict.PASS

    def test_gate_threshold_enforcement(self):
        """max_new_findings threshold triggers FAIL."""
        findings = [
            _make_diff_finding(severity=FindingSeverity.LOW),
            _make_diff_finding(severity=FindingSeverity.LOW),
            _make_diff_finding(severity=FindingSeverity.LOW),
        ]
        policy = RegressionGatePolicy(max_new_findings=2)
        result = evaluate_regression_gate(findings, policy)
        assert result.verdict == GateVerdict.FAIL

    def test_gate_unchanged_findings_not_evaluated(self):
        """UNCHANGED findings are not evaluated by the gate."""
        df = DifferentialFinding(
            finding=_make_finding(),
            transition=FindingTransition.UNCHANGED,
        )
        result = evaluate_regression_gate([df])
        assert result.verdict == GateVerdict.PASS
        assert result.total_new == 0
