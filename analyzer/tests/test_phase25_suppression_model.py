"""Phase 25 tests — Suppression model validation, expiration, scope matching."""

import pytest
from datetime import datetime, timezone, timedelta

from analyzer.models.suppression import (
    FindingSuppression,
    SuppressionKind,
    SuppressionScope,
)


class TestSuppressionModel:
    """Test suppression model creation and scope matching."""

    def test_suppression_creation(self):
        """FindingSuppression can be created with required fields."""
        s = FindingSuppression(
            suppression_id="SUP-001",
            kind=SuppressionKind.INLINE_ANNOTATION,
            scope=SuppressionScope.RULE_IN_FILE,
            target_rule_id="SEC-PY-005",
            target_file_path="src/db.py",
            reason="Parameterized in ORM layer",
        )
        assert s.suppression_id == "SUP-001"
        assert s.kind == SuppressionKind.INLINE_ANNOTATION
        assert s.is_active is True
        assert s.expires_at is None

    def test_suppression_scope_rule_matching(self):
        """RULE scope matches any finding with matching rule_id."""
        s = FindingSuppression(
            suppression_id="SUP-002",
            kind=SuppressionKind.CONFIG_EXCLUSION,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
        )
        assert s.matches_finding("SEC-PY-005", "any/file.py") is True
        assert s.matches_finding("SEC-PY-003", "any/file.py") is False

    def test_suppression_scope_rule_in_file_matching(self):
        """RULE_IN_FILE scope matches only when both rule and file match."""
        s = FindingSuppression(
            suppression_id="SUP-003",
            kind=SuppressionKind.INLINE_ANNOTATION,
            scope=SuppressionScope.RULE_IN_FILE,
            target_rule_id="SEC-PY-005",
            target_file_path="src/db.py",
        )
        assert s.matches_finding("SEC-PY-005", "src/db.py") is True
        assert s.matches_finding("SEC-PY-005", "src/other.py") is False
        assert s.matches_finding("SEC-PY-003", "src/db.py") is False

    def test_suppression_scope_file_matching(self):
        """FILE scope matches any finding in the target file."""
        s = FindingSuppression(
            suppression_id="SUP-004",
            kind=SuppressionKind.CONFIG_EXCLUSION,
            scope=SuppressionScope.FILE,
            target_file_path="legacy/migrations.py",
        )
        assert s.matches_finding("SEC-PY-005", "legacy/migrations.py") is True
        assert s.matches_finding("SEC-JS-003", "legacy/migrations.py") is True
        assert s.matches_finding("SEC-PY-005", "src/db.py") is False

    def test_suppression_scope_finding_fingerprint(self):
        """FINDING scope matches only when fingerprint primary_hash matches."""
        s = FindingSuppression(
            suppression_id="SUP-005",
            kind=SuppressionKind.FALSE_POSITIVE,
            scope=SuppressionScope.FINDING,
            target_fingerprint="abc123hash",
        )
        assert s.matches_finding("SEC-PY-005", "src/db.py", primary_hash="abc123hash") is True
        assert s.matches_finding("SEC-PY-005", "src/db.py", primary_hash="different") is False
        assert s.matches_finding("SEC-PY-005", "src/db.py") is False

    def test_suppression_expiration(self):
        """Timed deferral expires correctly."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        s = FindingSuppression(
            suppression_id="SUP-006",
            kind=SuppressionKind.TIMED_DEFERRAL,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
            expires_at=past,
        )
        assert s.is_expired() is True

    def test_suppression_not_expired(self):
        """Non-expired timed deferral returns False."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        s = FindingSuppression(
            suppression_id="SUP-007",
            kind=SuppressionKind.TIMED_DEFERRAL,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
            expires_at=future,
        )
        assert s.is_expired() is False

    def test_inactive_suppression_no_match(self):
        """Inactive suppressions never match."""
        s = FindingSuppression(
            suppression_id="SUP-008",
            kind=SuppressionKind.INLINE_ANNOTATION,
            scope=SuppressionScope.RULE,
            target_rule_id="SEC-PY-005",
            is_active=False,
        )
        assert s.matches_finding("SEC-PY-005", "src/db.py") is False
