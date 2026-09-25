"""Tests for Phase 20 security boundary model and cross-vulnerability sanitizer rejection."""

import pytest
from analyzer.dataflow.contracts.composition import CompatibilityState
from analyzer.dataflow.contracts.security_boundary import SecurityBoundaryModel
from analyzer.dataflow.taint.models import SinkCategory


def test_html_escape_rejected_for_sql_injection():
    """Verify that html.escape (DOM_INJECTION) is strictly rejected as a sanitizer for SQL execution."""
    model = SecurityBoundaryModel()
    status = model.evaluate_boundary(
        sink_rule_id="SEC-PY-011",
        sanitizer_rule_id="SANITIZER_DOM_INJECTION",
        sink_category=SinkCategory.SQL_EXECUTE,
        sanitizer_category="DOM_INJECTION",
    )
    assert status == CompatibilityState.VIOLATED


def test_html_escape_rejected_for_command_injection():
    """Verify that html.escape (DOM_INJECTION) is strictly rejected as a sanitizer for OS command injection."""
    model = SecurityBoundaryModel()
    status = model.evaluate_boundary(
        sink_rule_id="SEC-PY-012",
        sanitizer_rule_id="SANITIZER_DOM_INJECTION",
        sink_category=SinkCategory.COMMAND_EXECUTE,
        sanitizer_category="DOM_INJECTION",
    )
    assert status == CompatibilityState.VIOLATED


def test_shlex_quote_accepted_for_command_injection():
    """Verify that shlex.quote (COMMAND_EXECUTE) is accepted as a valid sanitizer for OS commands."""
    model = SecurityBoundaryModel()
    status = model.evaluate_boundary(
        sink_rule_id="SEC-PY-012",
        sanitizer_rule_id="SANITIZER_COMMAND_EXECUTE",
        sink_category=SinkCategory.COMMAND_EXECUTE,
        sanitizer_category="COMMAND_EXECUTE",
    )
    assert status == CompatibilityState.SATISFIED


def test_js_sanitize_html_rejected_for_js_sql_injection():
    """Verify JS sanitizeHtml (DOM_INJECTION) is rejected for SEC-JS-009 (SQL injection)."""
    model = SecurityBoundaryModel()
    status = model.evaluate_boundary(
        sink_rule_id="SEC-JS-009",
        sanitizer_rule_id="SANITIZER_DOM_INJECTION",
        sink_category=SinkCategory.SQL_EXECUTE,
        sanitizer_category="DOM_INJECTION",
    )
    assert status == CompatibilityState.VIOLATED


def test_unknown_sanitizer_rejected():
    """Verify unknown or unverified sanitizers fail closed (UNKNOWN != SAFE)."""
    model = SecurityBoundaryModel()
    status = model.evaluate_boundary(
        sink_rule_id="SEC-PY-011",
        sanitizer_rule_id="CUSTOM_MY_CLEANER",
        sink_category=SinkCategory.SQL_EXECUTE,
        sanitizer_category="CUSTOM_UNKNOWN",
    )
    assert status == CompatibilityState.VIOLATED
