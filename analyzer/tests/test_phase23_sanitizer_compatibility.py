"""Tests for Phase 23 sink-specific sanitizer compatibility matrix."""

import pytest
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.rules.policy import SecurityPolicyRegistry, PolicyEvaluationResult


def test_html_escape_does_not_sanitize_sql_sink():
    """HTML escaping must satisfy DOM sinks but NOT SQL execution sinks."""
    state = SecurityPropertyState().with_property(SecurityProperty.HTML_SAFE)

    # Valid for DOM
    assert state.is_safe_for_sink(SinkCategory.DOM_INJECTION) is True

    # Invalid for SQL and Command
    assert state.is_safe_for_sink(SinkCategory.SQL_EXECUTE) is False
    assert state.is_safe_for_sink(SinkCategory.COMMAND_EXECUTE) is False

    registry = SecurityPolicyRegistry(load_defaults=True)
    sql_policy = registry.get_policy("POL-SQL-01")
    outcome = sql_policy.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=state,
    )
    assert outcome.result == PolicyEvaluationResult.VIOLATED
    assert "SQL_SAFE" in outcome.missing_properties


def test_shell_quote_does_not_sanitize_sql_or_dom_sinks():
    """Shell quoting (shlex.quote) must satisfy Command sinks but NOT SQL or DOM sinks."""
    state = SecurityPropertyState().with_property(SecurityProperty.COMMAND_SAFE)

    # Valid for Command
    assert state.is_safe_for_sink(SinkCategory.COMMAND_EXECUTE) is True

    # Invalid for SQL and DOM
    assert state.is_safe_for_sink(SinkCategory.SQL_EXECUTE) is False
    assert state.is_safe_for_sink(SinkCategory.DOM_INJECTION) is False

    registry = SecurityPolicyRegistry(load_defaults=True)
    dom_policy = registry.get_policy("POL-DOM-01")
    outcome = dom_policy.evaluate(
        sink_category=SinkCategory.DOM_INJECTION,
        property_state=state,
    )
    assert outcome.result == PolicyEvaluationResult.VIOLATED


def test_numeric_validation_satisfies_all_scalar_sinks():
    """Type-level validation (e.g. integer cast) is universally safe for scalar injection sinks."""
    state = SecurityPropertyState().with_property(SecurityProperty.VALIDATED_TYPE)

    assert state.is_safe_for_sink(SinkCategory.SQL_EXECUTE) is True
    assert state.is_safe_for_sink(SinkCategory.COMMAND_EXECUTE) is True
    assert state.is_safe_for_sink(SinkCategory.DOM_INJECTION) is True
    assert state.is_safe_for_sink(SinkCategory.CODE_EVAL) is True


def test_allowed_sanitizer_exemption():
    """Directly recognized framework-specific sanitizers in policy definition provide safe exemption."""
    registry = SecurityPolicyRegistry(load_defaults=True)
    sql_policy = registry.get_policy("POL-SQL-01")

    outcome = sql_policy.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=SecurityPropertyState(),
        sanitizer_id="psycopg2.sql.Literal",
    )
    assert outcome.result == PolicyEvaluationResult.SATISFIED
