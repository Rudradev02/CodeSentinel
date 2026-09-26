"""Tests for Phase 23 security policy intelligence engine."""

import pytest
from analyzer.rules.policy import (
    SecurityPolicyRegistry,
    SecurityPolicy,
    PolicyEnforcementMode,
    PolicyEvaluationResult,
)
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.boundary import AuthenticationState, AuthorizationState


def test_default_policy_registry_loading():
    registry = SecurityPolicyRegistry(load_defaults=True)
    policies = registry.get_all_policies()
    policy_ids = {p.policy_id for p in policies}
    
    assert "POL-SQL-01" in policy_ids
    assert "POL-CMD-01" in policy_ids
    assert "POL-DOM-01" in policy_ids
    assert "POL-EVAL-01" in policy_ids
    assert "POL-AUTHZ-01" in policy_ids


def test_sql_policy_violated_without_escaped_property():
    registry = SecurityPolicyRegistry(load_defaults=True)
    sql_policy = registry.get_policy("POL-SQL-01")
    assert sql_policy is not None

    prop_state = SecurityPropertyState()
    # No properties added -> untrusted input reaches SQL sink
    eval_res = sql_policy.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=prop_state,
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert eval_res.result == PolicyEvaluationResult.VIOLATED
    assert "required properties" in eval_res.explanation


def test_sql_policy_satisfied_with_sql_safe():
    registry = SecurityPolicyRegistry(load_defaults=True)
    sql_policy = registry.get_policy("POL-SQL-01")
    assert sql_policy is not None

    prop_state = SecurityPropertyState().with_property(SecurityProperty.SQL_SAFE)

    eval_res = sql_policy.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=prop_state,
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert eval_res.result == PolicyEvaluationResult.SATISFIED


def test_cmd_policy_violated_vs_satisfied():
    registry = SecurityPolicyRegistry(load_defaults=True)
    cmd_policy = registry.get_policy("POL-CMD-01")
    assert cmd_policy is not None

    # Violated when unescaped
    res_violated = cmd_policy.evaluate(
        sink_category=SinkCategory.COMMAND_EXECUTE,
        property_state=SecurityPropertyState(),
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert res_violated.result == PolicyEvaluationResult.VIOLATED

    # Satisfied when escaped
    escaped_state = SecurityPropertyState().with_property(SecurityProperty.COMMAND_SAFE)
    res_satisfied = cmd_policy.evaluate(
        sink_category=SinkCategory.COMMAND_EXECUTE,
        property_state=escaped_state,
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert res_satisfied.result == PolicyEvaluationResult.SATISFIED


def test_dom_xss_policy():
    registry = SecurityPolicyRegistry(load_defaults=True)
    dom_policy = registry.get_policy("POL-DOM-01")
    assert dom_policy is not None

    res_violated = dom_policy.evaluate(
        sink_category=SinkCategory.DOM_INJECTION,
        property_state=SecurityPropertyState(),
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert res_violated.result == PolicyEvaluationResult.VIOLATED

    safe_state = SecurityPropertyState().with_property(SecurityProperty.HTML_SAFE)
    res_satisfied = dom_policy.evaluate(
        sink_category=SinkCategory.DOM_INJECTION,
        property_state=safe_state,
        auth_state=AuthenticationState.UNKNOWN,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert res_satisfied.result == PolicyEvaluationResult.SATISFIED


def test_authz_policy_requires_authorization():
    registry = SecurityPolicyRegistry(load_defaults=True)
    authz_policy = registry.get_policy("POL-AUTHZ-01")
    assert authz_policy is not None

    # Authenticated but NOT authorized -> VIOLATED
    res_auth_only = authz_policy.evaluate(
        sink_category=SinkCategory.CODE_EVAL,
        property_state=SecurityPropertyState(),
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.UNKNOWN,
    )
    assert res_auth_only.result == PolicyEvaluationResult.VIOLATED

    # Authorized -> SATISFIED
    res_authorized = authz_policy.evaluate(
        sink_category=SinkCategory.CODE_EVAL,
        property_state=SecurityPropertyState(),
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.ROLE_VERIFIED,
    )
    assert res_authorized.result == PolicyEvaluationResult.SATISFIED
