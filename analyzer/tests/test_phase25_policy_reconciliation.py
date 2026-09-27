"""Phase 25 tests — Policy-induced transition classification."""

import pytest

from analyzer.comparison.policy_reconciliation import (
    PolicyDiff,
    compute_policy_diff,
    classify_policy_induced_transition,
)
from analyzer.rules.policy import SecurityPolicy, PolicyEnforcementMode
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.dataflow.properties import SecurityProperty
from analyzer.models.findings import (
    Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence,
)


def _make_policy(policy_id, enforcement=PolicyEnforcementMode.ENFORCE, version=1, properties=None):
    return SecurityPolicy(
        policy_id=policy_id,
        version=version,
        name=f"Policy {policy_id}",
        description=f"Test policy {policy_id}",
        enforcement_mode=enforcement,
        required_security_properties=properties or [],
    )


def _make_finding(rule_id="SEC-PY-005", evidence=None):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="src/db.py", line_start=10),
        code_snippet="cursor.execute(query)",
        description="Test finding",
        remediation="Fix it",
        evidence=evidence or {},
    )


class TestPolicyDiff:
    """Test policy diff computation."""

    def test_added_policy(self):
        """New policy in current produces added_policy_ids."""
        baseline = [_make_policy("POL-SQL-01")]
        current = [_make_policy("POL-SQL-01"), _make_policy("POL-NEW-01")]
        diff = compute_policy_diff(baseline, current)
        assert "POL-NEW-01" in diff.added_policy_ids
        assert diff.has_changes is True

    def test_removed_policy(self):
        """Policy in baseline but not current produces removed_policy_ids."""
        baseline = [_make_policy("POL-SQL-01"), _make_policy("POL-OLD-01")]
        current = [_make_policy("POL-SQL-01")]
        diff = compute_policy_diff(baseline, current)
        assert "POL-OLD-01" in diff.removed_policy_ids

    def test_changed_policy_version(self):
        """Version bump produces changed_policy_ids."""
        baseline = [_make_policy("POL-SQL-01", version=1)]
        current = [_make_policy("POL-SQL-01", version=2)]
        diff = compute_policy_diff(baseline, current)
        assert "POL-SQL-01" in diff.changed_policy_ids

    def test_enforcement_mode_change(self):
        """Enforcement mode change is tracked."""
        baseline = [_make_policy("POL-SQL-01", enforcement=PolicyEnforcementMode.ADVISORY)]
        current = [_make_policy("POL-SQL-01", enforcement=PolicyEnforcementMode.ENFORCE)]
        diff = compute_policy_diff(baseline, current)
        assert "POL-SQL-01" in diff.enforcement_changes
        old, new = diff.enforcement_changes["POL-SQL-01"]
        assert old == "ADVISORY"
        assert new == "ENFORCE"

    def test_no_changes(self):
        """Identical policies produce empty diff."""
        policies = [_make_policy("POL-SQL-01")]
        diff = compute_policy_diff(policies, policies)
        assert diff.has_changes is False


class TestPolicyInducedClassification:
    """Test policy-induced transition classification."""

    def test_new_finding_from_added_policy(self):
        """New finding associated with added policy → POLICY_INDUCED_NEW."""
        diff = PolicyDiff(added_policy_ids={"POL-NEW-01"})
        finding = _make_finding(evidence={"policy_id": "POL-NEW-01"})
        result = classify_policy_induced_transition(finding, diff, is_new=True)
        assert result == "POLICY_INDUCED_NEW"

    def test_resolved_finding_from_removed_policy(self):
        """Resolved finding from removed policy → POLICY_INDUCED_RESOLVED."""
        diff = PolicyDiff(removed_policy_ids={"POL-OLD-01"})
        finding = _make_finding(evidence={"policy_id": "POL-OLD-01"})
        result = classify_policy_induced_transition(finding, diff, is_new=False)
        assert result == "POLICY_INDUCED_RESOLVED"

    def test_enforcement_upgrade_produces_new(self):
        """ADVISORY → ENFORCE on a policy → POLICY_INDUCED_NEW for new findings."""
        diff = PolicyDiff(enforcement_changes={"POL-SQL-01": ("ADVISORY", "ENFORCE")})
        finding = _make_finding()
        result = classify_policy_induced_transition(finding, diff, is_new=True)
        assert result == "POLICY_INDUCED_NEW"

    def test_no_policy_change_returns_none(self):
        """No policy changes → None (not policy-induced)."""
        diff = PolicyDiff()
        finding = _make_finding()
        result = classify_policy_induced_transition(finding, diff, is_new=True)
        assert result is None
