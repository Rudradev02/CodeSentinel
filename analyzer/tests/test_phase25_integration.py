"""Phase 25 tests — End-to-end lifecycle, regression, and gate integration."""

import pytest

from analyzer.incremental.finding_fingerprint import compute_fingerprint_for_finding
from analyzer.comparison.regression import RegressionClassifier, RegressionCause, RegressionSeverity
from analyzer.comparison.gate import evaluate_regression_gate, RegressionGatePolicy, GateVerdict
from analyzer.comparison.policy_reconciliation import PolicyDiff, classify_policy_induced_transition
from analyzer.rules.suppression_engine import SuppressionEngine
from analyzer.models.suppression import FindingSuppression, SuppressionKind, SuppressionScope
from analyzer.models.comparison import (
    DifferentialFinding,
    FindingTransition,
    FindingLifecycleState,
    ComparisonSummary,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence


def _make_finding(
    rule_id="SEC-PY-005",
    file_path="src/db.py",
    line=10,
    snippet="cursor.execute(query)",
    severity=FindingSeverity.HIGH,
):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path=file_path, line_start=line),
        code_snippet=snippet,
        description="SQL injection",
        remediation="Use parameterized queries",
    )


class TestPhase25Integration:
    """End-to-end integration tests for the Phase 25 lifecycle pipeline."""

    def test_full_regression_pipeline(self):
        """Finding → Fingerprint → Classification → Gate verdict."""
        # 1. Create finding
        finding = _make_finding(severity=FindingSeverity.CRITICAL)

        # 2. Compute fingerprint
        fp = compute_fingerprint_for_finding(finding)
        assert fp.primary_hash
        assert fp.stable_id.startswith("CS-SEC-PY-005-")

        # 3. Classify regression
        classification = RegressionClassifier.classify(
            finding,
            changed_files={"src/db.py"},
        )
        assert classification.cause == RegressionCause.CODE_CHANGE
        assert classification.severity == RegressionSeverity.BLOCKING

        # 4. Build differential finding
        df = DifferentialFinding(
            finding=finding,
            transition=FindingTransition.NEW,
            lifecycle_state=FindingLifecycleState.REGRESSION,
            regression=classification,
        )

        # 5. Evaluate gate
        gate_result = evaluate_regression_gate([df])
        assert gate_result.verdict == GateVerdict.FAIL
        assert gate_result.total_blocking == 1

    def test_suppression_prevents_gate_failure(self):
        """Suppressed critical finding does not trigger gate failure."""
        finding = _make_finding(severity=FindingSeverity.CRITICAL)

        # Create suppression
        suppression = FindingSuppression(
            suppression_id="SUP-001",
            kind=SuppressionKind.INLINE_ANNOTATION,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
            reason="Acknowledged, tracked in JIRA-1234",
        )

        # Suppression engine matches
        engine = SuppressionEngine([suppression])
        match = engine.match_finding(finding)
        assert match is not None

        # Gate ignores suppressed
        df = DifferentialFinding(
            finding=finding,
            transition=FindingTransition.NEW,
            suppression=suppression,
        )
        gate_result = evaluate_regression_gate([df], RegressionGatePolicy(ignore_suppressed=True))
        assert gate_result.verdict == GateVerdict.PASS

    def test_policy_induced_finding_classification(self):
        """Policy-induced findings are classified and ignored by gate."""
        finding = _make_finding(file_path="src/unchanged.py")

        # Classify with policy change
        classification = RegressionClassifier.classify(
            finding,
            changed_files=set(),
            policy_hash_changed=True,
            policy_id="POL-SQL-01",
        )
        assert classification.cause == RegressionCause.POLICY_CHANGE

        # Policy diff confirms
        diff = PolicyDiff(added_policy_ids={"POL-SQL-01"})
        transition = classify_policy_induced_transition(finding, diff, is_new=True)
        assert transition == "POLICY_INDUCED_NEW"

        # Gate ignores
        df = DifferentialFinding(
            finding=finding,
            transition=FindingTransition.NEW,
            lifecycle_state=FindingLifecycleState.POLICY_INDUCED_NEW,
            regression=classification,
        )
        gate_result = evaluate_regression_gate([df], RegressionGatePolicy(ignore_policy_induced=True))
        assert gate_result.verdict == GateVerdict.PASS

    def test_comparison_summary_lifecycle_counters(self):
        """ComparisonSummary lifecycle counters are serializable."""
        summary = ComparisonSummary(
            total_current=10,
            total_baseline=8,
            new_count=3,
            resolved_count=1,
            unchanged_count=5,
            modified_count=1,
            regression_count=2,
            policy_induced_new_count=1,
            suppressed_count=1,
            gate_verdict="FAIL",
        )
        data = summary.model_dump()
        assert data["regression_count"] == 2
        assert data["policy_induced_new_count"] == 1
        assert data["gate_verdict"] == "FAIL"

        # Roundtrip
        restored = ComparisonSummary(**data)
        assert restored.regression_count == 2
