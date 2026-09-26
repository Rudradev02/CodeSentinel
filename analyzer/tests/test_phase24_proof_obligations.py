"""Unit tests for Phase 24 Policy Proof Obligations and Verification Diagnostics."""

import pytest
from analyzer.models.obligation import (
    ObligationKind,
    ObligationEvaluationState,
    PolicyProofObligation,
)
from analyzer.models.boundary import (
    TrustBoundaryType,
    AuthenticationState,
    AuthorizationState,
)
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.rules.policy import (
    SecurityPolicy,
    SecurityPolicyRegistry,
    PolicyEnforcementMode,
    PolicyEvaluationResult,
)


def test_obligation_model_serialization():
    """Verify PolicyProofObligation model serialization and immutability."""
    obl = PolicyProofObligation(
        obligation_id="OBL_AUTH_POL_001",
        policy_id="POL_001",
        kind=ObligationKind.REQUIRES_AUTHENTICATION,
        target_sink_category=SinkCategory.SQL_EXECUTE,
        state=ObligationEvaluationState.PROVEN_SAFE,
        evidence_details="Route decorator @login_required verifies session",
    )
    dumped = obl.model_dump(mode="json")
    assert dumped["obligation_id"] == "OBL_AUTH_POL_001"
    assert dumped["kind"] == "REQUIRES_AUTHENTICATION"
    assert dumped["state"] == "PROVEN_SAFE"
    assert dumped["target_sink_category"] == "SQL_EXECUTE"
    assert dumped["unknown_reason"] is None


def test_policy_generates_proof_obligations_structure():
    """Verify SecurityPolicy generates structured proof obligations."""
    pol = SecurityPolicy(
        policy_id="POL-TEST-01",
        name="Test Data Policy",
        description="Requires authentication, authorization, and SQL_SAFE property",
        source_boundaries=[TrustBoundaryType.HTTP_REQUEST_PARAM],
        target_sink_categories=[SinkCategory.SQL_EXECUTE],
        require_authentication=True,
        require_authorization=True,
        required_security_properties=[SecurityProperty.SQL_SAFE],
    )
    obligations = pol.generate_proof_obligations()
    assert len(obligations) == 3
    kinds = [o.kind for o in obligations]
    assert ObligationKind.REQUIRES_AUTHENTICATION in kinds
    assert ObligationKind.REQUIRES_AUTHORIZATION in kinds
    assert ObligationKind.REQUIRES_PROPERTY in kinds


def test_policy_evaluation_obligation_states_proven_safe():
    """Verify evaluation marks all obligations PROVEN_SAFE when conditions met."""
    pol = SecurityPolicy(
        policy_id="POL-TEST-02",
        name="Strict SQL Policy",
        description="Requires authentication and SQL_SAFE property",
        target_sink_categories=[SinkCategory.SQL_EXECUTE],
        require_authentication=True,
        required_security_properties=[SecurityProperty.SQL_SAFE],
    )
    st = SecurityPropertyState()
    st.add_property(SecurityProperty.SQL_SAFE)

    outcome = pol.evaluate(
        sink_category=SinkCategory.SQL_EXECUTE,
        property_state=st,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.AUTHORIZED,
    )
    assert outcome.result == PolicyEvaluationResult.SATISFIED
    assert len(outcome.missing_properties) == 0
    assert len(outcome.unknown_reasons) == 0

    assert len(outcome.proof_obligations) == 2
    for obl in outcome.proof_obligations:
        assert obl.state == ObligationEvaluationState.PROVEN_SAFE


def test_policy_evaluation_obligation_states_unknown():
    """Verify evaluation captures indeterminate context with UNKNOWN state and diagnostic reason."""
    pol = SecurityPolicy(
        policy_id="POL-TEST-03",
        name="Boundary Auth Policy",
        description="Requires authentication",
        target_sink_categories=[SinkCategory.COMMAND_EXECUTE],
        require_authentication=True,
        required_security_properties=[SecurityProperty.COMMAND_SAFE],
    )
    # Default unpopulated state has SecurityProperty.UNKNOWN
    st = SecurityPropertyState()

    outcome = pol.evaluate(
        sink_category=SinkCategory.COMMAND_EXECUTE,
        property_state=st,
        auth_state=AuthenticationState.UNKNOWN,
    )
    assert outcome.result == PolicyEvaluationResult.VIOLATED
    assert len(outcome.unknown_reasons) > 0

    auth_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_AUTHENTICATION)
    assert auth_obl.state == ObligationEvaluationState.UNKNOWN
    assert auth_obl.unknown_reason is not None

    prop_obl = next(o for o in outcome.proof_obligations if o.kind == ObligationKind.REQUIRES_PROPERTY)
    assert prop_obl.state == ObligationEvaluationState.UNKNOWN
    assert prop_obl.unknown_reason is not None


def test_policy_registry_conflict_detection():
    """Verify SecurityPolicyRegistry detects invariant conflicts between applicable policies."""
    reg = SecurityPolicyRegistry(load_defaults=False)
    p1 = SecurityPolicy(
        policy_id="POL-P1",
        name="Mandatory Auth",
        description="Requires authentication",
        target_sink_categories=[SinkCategory.SQL_EXECUTE],
        require_authentication=True,
    )
    p2 = SecurityPolicy(
        policy_id="POL-P2",
        name="Public Access",
        description="Explicitly permits anonymous access",
        target_sink_categories=[SinkCategory.SQL_EXECUTE],
        require_authentication=False,
    )
    reg.register_policy(p1)
    reg.register_policy(p2)

    applicable = reg.get_applicable_policies(sink_category=SinkCategory.SQL_EXECUTE)
    assert len(applicable) == 2
    conflicts = reg.detect_policy_conflicts(applicable)
    assert len(conflicts) == 1
    assert "POL-P1" in conflicts[0]
    assert "POL-P2" in conflicts[0]
