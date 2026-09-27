"""Phase 25 tests — Inline suppression annotation parsing (Python #, JS //)."""

import pytest

from analyzer.rules.suppression_parser import (
    parse_inline_suppressions,
    parse_config_suppressions,
)
from analyzer.models.suppression import SuppressionKind, SuppressionScope


class TestInlineSuppressionParser:
    """Test inline suppression annotation parsing from source comments."""

    def test_python_single_rule_suppression(self):
        """Parse simple # codesentinel-suppress RULE-ID annotation."""
        source = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # codesentinel-suppress SEC-PY-005
    return db.execute(query)
'''
        suppressions = parse_inline_suppressions(source, "src/db.py", "PYTHON")
        assert len(suppressions) == 1
        assert suppressions[0].target_rule_id == "SEC-PY-005"
        assert suppressions[0].scope == SuppressionScope.RULE_IN_FILE
        assert suppressions[0].kind == SuppressionKind.INLINE_ANNOTATION

    def test_python_suppression_with_reason(self):
        """Parse suppression with reason= attribute."""
        source = '# codesentinel-suppress SEC-PY-005 reason="Parameterized in ORM layer"'
        suppressions = parse_inline_suppressions(source, "src/db.py", "PYTHON")
        assert len(suppressions) == 1
        assert suppressions[0].reason == "Parameterized in ORM layer"

    def test_python_suppression_with_until(self):
        """Parse suppression with until= expiration date."""
        source = '# codesentinel-suppress SEC-PY-005 until=2025-12-31'
        suppressions = parse_inline_suppressions(source, "src/db.py", "PYTHON")
        assert len(suppressions) == 1
        assert suppressions[0].kind == SuppressionKind.TIMED_DEFERRAL
        assert suppressions[0].expires_at is not None
        assert suppressions[0].expires_at.year == 2025
        assert suppressions[0].expires_at.month == 12

    def test_javascript_suppression(self):
        """Parse // codesentinel-suppress annotation in JavaScript."""
        source = '// codesentinel-suppress SEC-JS-003 reason="Sanitized by DOMPurify"'
        suppressions = parse_inline_suppressions(source, "src/app.js", "JAVASCRIPT")
        assert len(suppressions) == 1
        assert suppressions[0].target_rule_id == "SEC-JS-003"
        assert suppressions[0].reason == "Sanitized by DOMPurify"

    def test_multi_rule_suppression(self):
        """Parse comma-separated rule IDs in single annotation."""
        source = '# codesentinel-suppress SEC-PY-005, SEC-PY-009'
        suppressions = parse_inline_suppressions(source, "src/db.py", "PYTHON")
        assert len(suppressions) == 2
        rule_ids = {s.target_rule_id for s in suppressions}
        assert rule_ids == {"SEC-PY-005", "SEC-PY-009"}

    def test_no_suppressions_in_clean_file(self):
        """Files without annotations produce no suppressions."""
        source = '''
def clean_function():
    return 42
'''
        suppressions = parse_inline_suppressions(source, "src/clean.py", "PYTHON")
        assert len(suppressions) == 0


class TestConfigSuppressionParser:
    """Test config-based suppression parsing from .codesentinel.yaml structure."""

    def test_config_rule_in_file_suppression(self):
        """Parse config suppression with rule_id and file."""
        configs = [
            {"rule_id": "SEC-PY-005", "file": "legacy/migrations.py", "reason": "Legacy code"}
        ]
        suppressions = parse_config_suppressions(configs)
        assert len(suppressions) == 1
        assert suppressions[0].scope == SuppressionScope.RULE_IN_FILE
        assert suppressions[0].target_rule_id == "SEC-PY-005"

    def test_config_rule_scope_suppression(self):
        """Parse config suppression with scope=RULE."""
        configs = [{"rule_id": "SEC-JS-003", "scope": "RULE", "reason": "React sanitized"}]
        suppressions = parse_config_suppressions(configs)
        assert len(suppressions) == 1
        assert suppressions[0].scope == SuppressionScope.RULE

    def test_config_with_expiration(self):
        """Parse config suppression with expires date."""
        configs = [
            {"rule_id": "SEC-PY-005", "file": "src/db.py", "expires": "2025-12-31"}
        ]
        suppressions = parse_config_suppressions(configs)
        assert len(suppressions) == 1
        assert suppressions[0].kind == SuppressionKind.TIMED_DEFERRAL
        assert suppressions[0].expires_at is not None
