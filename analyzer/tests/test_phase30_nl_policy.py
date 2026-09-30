"""Unit tests for Phase 30 Natural-Language Security Policy Validation in analyzer.

Validates:
- Semantic validation of SecurityPolicyCandidateDTO.
- Rejection of ambiguous/vague directives.
- Contradiction detection between authentication requirements and anonymous boundaries.
- Rejection of unregistered/unsupported sanitizers.
- Direct activation in SecurityPolicyRegistry.
"""

import pytest

from analyzer.dataflow.properties import SecurityProperty
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.boundary import TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.rules.policy import PolicyEnforcementMode, SecurityPolicy, SecurityPolicyRegistry
from analyzer.rules.policy_authoring import (
    PolicyValidationStatus,
    SecurityPolicyCandidateDTO,
    SemanticPolicyValidator,
)


def test_valid_sql_policy_candidate_validation():
    """Validates valid candidate and converts to SecurityPolicy model."""
    candidate_dict = {
        "policy_id": "POL-SQL-01",
        "name": "SQL Query Parameterization Policy",
        "description": "Requires all SQL execution operations from HTTP parameters to be parameterized or sanitized.",
        "source_boundaries": ["HTTP_REQUEST_PARAM", "HTTP_REQUEST_BODY"],
        "target_sink_categories": ["SQL_EXECUTE"],
        "required_security_properties": ["SQL_PARAMETRIZED"],
        "allowed_sanitizers": ["int", "psycopg2.sql.Literal"],
        "require_authentication": True,
        "require_authorization": False,
        "enforcement_mode": "ENFORCE",
        "associated_rule_ids": ["SEC-PY-005"],
        "severity": "HIGH",
    }
    raw_prompt = "All SQL queries originating from HTTP request parameters must use parameterized queries or integer casting."

    val_status, policy, val_diag = SemanticPolicyValidator.validate(candidate_dict, raw_prompt=raw_prompt)
    assert val_status == PolicyValidationStatus.VALIDATED_CANDIDATE
    assert isinstance(policy, SecurityPolicy)
    assert policy.policy_id == "POL-SQL-01"
    assert SinkCategory.SQL_EXECUTE in policy.target_sink_categories
    assert SecurityProperty.SQL_SAFE in policy.required_security_properties
    assert policy.require_authentication is True
    assert policy.enforcement_mode == PolicyEnforcementMode.ENFORCE
    assert policy.severity == FindingSeverity.HIGH


def test_ambiguous_prompt_rejection():
    """Rejects candidate JSON with vague terms and missing sinks/properties."""
    vague_candidate = {
        "policy_id": "POL-SAFE-01",
        "name": "Completely Safe System",
        "description": "Make the code safe and clean.",
        "target_sink_categories": [],
        "required_security_properties": [],
    }
    status, policy, diagnostics = SemanticPolicyValidator.validate(vague_candidate, raw_prompt="Be clean and safe")
    assert status == PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS
    assert policy is None
    assert any("Vague" in d or "no target sink" in d for d in diagnostics)


def test_contradictory_auth_policy():
    """Rejects policy demanding authentication while source is unauthenticated boundary."""
    contradictory_candidate = {
        "policy_id": "POL-AUTH-01",
        "name": "Contradictory Auth Policy",
        "description": "Requires authentication on public internet unauthenticated inputs.",
        "source_boundaries": ["PUBLIC_INTERNET_UNAUTHENTICATED"],
        "target_sink_categories": ["SQL_EXECUTE"],
        "required_security_properties": ["SQL_PARAMETRIZED"],
        "allowed_sanitizers": ["int"],
        "require_authentication": True,  # Contradiction with PUBLIC_INTERNET_UNAUTHENTICATED
        "require_authorization": False,
        "enforcement_mode": "ENFORCE",
    }
    status, policy, diagnostics = SemanticPolicyValidator.validate(contradictory_candidate)
    assert status == PolicyValidationStatus.CONTRADICTORY
    assert policy is None
    assert any("Contradictory" in d for d in diagnostics)


def test_unsupported_sanitizer_rejection():
    """Rejects candidate proposing unrecognized sanitizer function."""
    invalid_sanitizer_candidate = {
        "policy_id": "POL-SAN-01",
        "name": "Invalid Sanitizer Policy",
        "description": "Uses nonexistent magic sanitizer.",
        "source_boundaries": ["HTTP_REQUEST_PARAM"],
        "target_sink_categories": ["SQL_EXECUTE"],
        "required_security_properties": ["SQL_PARAMETRIZED"],
        "allowed_sanitizers": ["custom_nonexistent_cleaner_xyz"],
        "require_authentication": False,
        "enforcement_mode": "ENFORCE",
    }
    status, policy, diagnostics = SemanticPolicyValidator.validate(invalid_sanitizer_candidate)
    assert status == PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS
    assert policy is None
    assert any("not in the recognized sanitizer registry" in d for d in diagnostics)


def test_policy_registry_integration():
    """Verifies that validated policies can be registered directly into SecurityPolicyRegistry."""
    registry = SecurityPolicyRegistry(load_defaults=False)
    assert registry.get_policy("POL-SQL-01") is None

    candidate_dict = {
        "policy_id": "POL-SQL-01",
        "name": "SQL Query Parameterization Policy",
        "description": "Requires all SQL execution operations from HTTP parameters to be parameterized.",
        "target_sink_categories": ["SQL_EXECUTE"],
        "required_security_properties": ["SQL_PARAMETRIZED"],
        "enforcement_mode": "ENFORCE",
    }
    status, policy, diags = SemanticPolicyValidator.validate(candidate_dict)
    assert status == PolicyValidationStatus.VALIDATED_CANDIDATE
    assert policy is not None

    registry.register_policy(policy)
    retrieved = registry.get_policy("POL-SQL-01")
    assert retrieved is not None
    assert retrieved.name == "SQL Query Parameterization Policy"
