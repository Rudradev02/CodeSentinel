"""Phase 25 tests — Extended lifecycle state machine transitions."""

import pytest

from analyzer.models.comparison import (
    FindingTransition,
    FindingLifecycleState,
    DifferentialFinding,
    ComparisonSummary,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence


def _make_finding(rule_id="SEC-PY-005"):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="src/db.py", line_start=10),
        code_snippet="cursor.execute(query)",
        description="Raw SQL query string construction",
        remediation="Use parameterized queries",
    )


class TestFindingLifecycleState:
    """Test the extended lifecycle state machine."""

    def test_lifecycle_state_enum_members(self):
        """All 11 lifecycle states exist."""
        expected = {
            "NEW", "RESOLVED", "UNCHANGED", "MODIFIED",
            "SUPPRESSED", "DEFERRED", "REOPENED",
            "POLICY_INDUCED_NEW", "POLICY_INDUCED_RESOLVED",
            "REGRESSION", "PERSISTENT",
        }
        actual = {s.value for s in FindingLifecycleState}
        assert expected == actual

    def test_lifecycle_backward_compatible_with_transition(self):
        """All FindingTransition values have corresponding FindingLifecycleState values."""
        for t in FindingTransition:
            lifecycle = FindingLifecycleState(t.value)
            assert lifecycle.value == t.value

    def test_differential_finding_lifecycle_field(self):
        """DifferentialFinding accepts optional lifecycle_state."""
        df = DifferentialFinding(
            finding=_make_finding(),
            transition=FindingTransition.NEW,
            lifecycle_state=FindingLifecycleState.REGRESSION,
        )
        assert df.lifecycle_state == FindingLifecycleState.REGRESSION

    def test_differential_finding_backward_compatible(self):
        """DifferentialFinding without lifecycle_state is backward-compatible."""
        df = DifferentialFinding(
            finding=_make_finding(),
            transition=FindingTransition.NEW,
        )
        assert df.lifecycle_state is None
        assert df.regression is None
        assert df.suppression is None

    def test_comparison_summary_lifecycle_counters(self):
        """ComparisonSummary includes Phase 25 lifecycle counters with defaults."""
        summary = ComparisonSummary()
        assert summary.suppressed_count == 0
        assert summary.deferred_count == 0
        assert summary.reopened_count == 0
        assert summary.policy_induced_new_count == 0
        assert summary.policy_induced_resolved_count == 0
        assert summary.regression_count == 0
        assert summary.pre_existing_count == 0
        assert summary.gate_verdict is None
