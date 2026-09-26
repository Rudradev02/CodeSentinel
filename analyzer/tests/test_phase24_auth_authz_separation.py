"""Unit tests for Phase 24 independent Authentication and Authorization separation."""

import pytest
from analyzer.models.boundary import AuthenticationState, AuthorizationState
from analyzer.models.obligation import ObligationKind, ObligationEvaluationState
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.rules.policy import SecurityPolicy, PolicyEvaluationResult


def test_auth_without_authz():
    """Verify an authenticated caller lacking authorization fails authorization obligation."""
    pol = SecurityPolicy(
        policy_id="POL-ADMIN-ONLY",
        name="Admin Resource Access",
        description="Requires both authentication and role verification",
        target_sink_categories=[SinkCategory.FILE_PATH],
        require_authentication=True,
        require_authorization=True,
    )
    st = SecurityPropertyState()

    outcome = pol.evaluate(
        sink_category=SinkCategory.FILE_PATH,
        property_state=st,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.UNAUTHORIZED,
    )
    assert outcome.result == PolicyEvaluationResult.VIOLATED
    auth_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHENTICATION)
    assert auth_obl.state == ObligationEvaluationState.PROVEN_SAFE

    authz_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHORIZATION)
    assert authz_obl.state == ObligationEvaluationState.PROVEN_VIOLATION


def test_authz_without_auth():
    """Verify unauthenticated caller fails authentication obligation even if role claim exists."""
    pol = SecurityPolicy(
        policy_id="POL-STRICT-AUTH",
        name="Strict Identity",
        description="Requires valid authentication",
        target_sink_categories=[SinkCategory.COMMAND_EXECUTE],
        require_authentication=True,
        require_authorization=True,
    )
    st = SecurityPropertyState()

    outcome = pol.evaluate(
        sink_category=SinkCategory.COMMAND_EXECUTE,
        property_state=st,
        auth_state=AuthenticationState.UNAUTHENTICATED,
        authz_state=AuthorizationState.AUTHORIZED,
    )
    assert outcome.result == PolicyEvaluationResult.VIOLATED
    auth_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHENTICATION)
    assert auth_obl.state == ObligationEvaluationState.PROVEN_VIOLATION

    authz_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHORIZATION)
    assert authz_obl.state == ObligationEvaluationState.PROVEN_SAFE


def test_both_authenticated_and_authorized():
    """Verify both authentication and authorization proof obligations are satisfied."""
    pol = SecurityPolicy(
        policy_id="POL-COMPLIANT",
        name="Fully Protected Endpoint",
        description="Requires verified session and granted permission",
        target_sink_categories=[SinkCategory.SQL_EXECUTE],
        require_authentication=True,
        require_authorization=True,
    )
    st = SecurityPropertyState()

    outcome = pol.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=st,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.ROLE_VERIFIED,
    )
    assert outcome.result == PolicyEvaluationResult.SATISFIED
    auth_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHENTICATION)
    assert auth_obl.state == ObligationEvaluationState.PROVEN_SAFE

    authz_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHORIZATION)
    assert authz_obl.state == ObligationEvaluationState.PROVEN_SAFE
