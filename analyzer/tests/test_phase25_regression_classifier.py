"""Phase 25 tests — Regression cause and severity classification."""

import pytest

from analyzer.comparison.regression import (
    RegressionClassifier,
    RegressionCause,
    RegressionSeverity,
    RegressionClassification,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence


def _make_finding(
    rule_id="SEC-PY-005",
    file_path="src/db.py",
    severity=FindingSeverity.HIGH,
):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path=file_path, line_start=10),
        code_snippet="cursor.execute(query)",
        description="Raw SQL query string construction",
        remediation="Use parameterized queries",
    )


class TestRegressionClassifier:
    """Test regression cause and severity classification."""

    def test_code_change_regression_critical(self):
        """Finding in modified file with CRITICAL severity → BLOCKING."""
        finding = _make_finding(severity=FindingSeverity.CRITICAL)
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/db.py"},
        )
        assert result.cause == RegressionCause.CODE_CHANGE
        assert result.severity == RegressionSeverity.BLOCKING
        assert result.is_in_changed_code is True

    def test_code_change_regression_high(self):
        """Finding in modified file with HIGH severity → BLOCKING."""
        finding = _make_finding(severity=FindingSeverity.HIGH)
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/db.py"},
        )
        assert result.cause == RegressionCause.CODE_CHANGE
        assert result.severity == RegressionSeverity.BLOCKING

    def test_code_change_regression_medium(self):
        """Finding in modified file with MEDIUM severity → ACTIONABLE."""
        finding = _make_finding(severity=FindingSeverity.MEDIUM)
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/db.py"},
        )
        assert result.cause == RegressionCause.CODE_CHANGE
        assert result.severity == RegressionSeverity.ACTIONABLE

    def test_code_change_regression_low(self):
        """Finding in modified file with LOW severity → ADVISORY."""
        finding = _make_finding(severity=FindingSeverity.LOW)
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/db.py"},
        )
        assert result.cause == RegressionCause.CODE_CHANGE
        assert result.severity == RegressionSeverity.ADVISORY

    def test_policy_induced_new(self):
        """New finding in unchanged code when policy_hash differs → POLICY_CHANGE."""
        finding = _make_finding(file_path="src/unchanged.py")
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/other_file.py"},
            policy_hash_changed=True,
            policy_id="POL-SQL-01",
        )
        assert result.cause == RegressionCause.POLICY_CHANGE
        assert result.severity == RegressionSeverity.ADVISORY
        assert result.is_in_changed_code is False
        assert result.policy_id == "POL-SQL-01"

    def test_config_change_rules_hash(self):
        """Finding in unchanged code with rules_hash change → CONFIG_CHANGE."""
        finding = _make_finding(file_path="src/stable.py")
        result = RegressionClassifier.classify(
            finding,
            changed_files=set(),
            rules_hash_changed=True,
        )
        assert result.cause == RegressionCause.CONFIG_CHANGE
        assert result.config_scope == "rules_hash"

    def test_framework_change(self):
        """Finding in unchanged code with framework_model_hash change → FRAMEWORK_CHANGE."""
        finding = _make_finding(file_path="src/app.py")
        result = RegressionClassifier.classify(
            finding,
            changed_files=set(),
            framework_model_hash_changed=True,
        )
        assert result.cause == RegressionCause.FRAMEWORK_CHANGE
        assert result.severity == RegressionSeverity.ADVISORY

    def test_pre_existing_finding(self):
        """Finding in unchanged code with no config changes → PRE_EXISTING."""
        finding = _make_finding(file_path="src/legacy.py")
        result = RegressionClassifier.classify(
            finding,
            changed_files={"src/completely_different.py"},
        )
        assert result.cause == RegressionCause.PRE_EXISTING
        assert result.severity == RegressionSeverity.ADVISORY
        assert result.is_in_changed_code is False

    def test_affected_files_treated_as_changed(self):
        """Findings in transitively affected files are classified as code change."""
        finding = _make_finding(file_path="src/db.py")
        result = RegressionClassifier.classify(
            finding,
            changed_files=set(),
            affected_files={"src/db.py"},
        )
        assert result.cause == RegressionCause.CODE_CHANGE
        assert result.is_in_changed_code is True
