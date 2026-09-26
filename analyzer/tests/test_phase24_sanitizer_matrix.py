"""Unit tests for Phase 24 Cross-Language Sanitizer Matrix and Category Compatibility."""

import pytest
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.rules.policy import SecurityPolicy, SecurityPolicyRegistry, PolicyEvaluationResult
from analyzer.models.obligation import ObligationKind, ObligationEvaluationState


def test_sql_sanitizer_compatibility():
    """Verify integer and literal sanitizers satisfy SQL policies while shlex quotes fail."""
    reg = SecurityPolicyRegistry(load_defaults=True)
    sql_pol = reg.get_policy("POL-SQL-01")
    assert sql_pol is not None

    st = SecurityPropertyState()
    # Compatible: 'int'
    outcome_ok = reg.evaluate_policy_outcome(
        policy=sql_pol,
        property_state=st,
        sanitizer_id="int",
        sink_category=SinkCategory.SQL_EXECUTE,
    )
    assert outcome_ok.result == PolicyEvaluationResult.SATISFIED
    san_obl = next(o for o in outcome_ok.proof_obligations if o.kind == ObligationKind.REQUIRES_SANITIZER)
    assert san_obl.state == ObligationEvaluationState.PROVEN_SAFE

    # Incompatible sanitizer for SQL: 'shlex.quote'
    outcome_bad = reg.evaluate_policy_outcome(
        policy=sql_pol,
        property_state=st,
        sanitizer_id="shlex.quote",
        sink_category=SinkCategory.SQL_EXECUTE,
    )
    assert outcome_bad.result == PolicyEvaluationResult.VIOLATED


def test_command_sanitizer_compatibility():
    """Verify shlex.quote satisfies command execution policies."""
    reg = SecurityPolicyRegistry(load_defaults=True)
    cmd_pol = reg.get_policy("POL-CMD-01")
    assert cmd_pol is not None

    st = SecurityPropertyState()
    outcome_ok = reg.evaluate_policy_outcome(
        policy=cmd_pol,
        property_state=st,
        sanitizer_id="shlex.quote",
        sink_category=SinkCategory.COMMAND_EXECUTE,
    )
    assert outcome_ok.result == PolicyEvaluationResult.SATISFIED


def test_xss_html_sanitizer_compatibility():
    """Verify DOMPurify.sanitize and html.escape satisfy XSS policies."""
    reg = SecurityPolicyRegistry(load_defaults=True)
    xss_pol = reg.get_policy("POL-XSS-01")
    assert xss_pol is not None

    st = SecurityPropertyState()
    outcome_dompurify = reg.evaluate_policy_outcome(
        policy=xss_pol,
        property_state=st,
        sanitizer_id="DOMPurify.sanitize",
        sink_category=SinkCategory.DOM_XSS,
    )
    assert outcome_dompurify.result == PolicyEvaluationResult.SATISFIED

    outcome_escape = reg.evaluate_policy_outcome(
        policy=xss_pol,
        property_state=st,
        sanitizer_id="html.escape",
        sink_category=SinkCategory.DOM_XSS,
    )
    assert outcome_escape.result == PolicyEvaluationResult.SATISFIED
