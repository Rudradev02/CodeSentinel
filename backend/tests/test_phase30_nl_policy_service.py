"""Unit and integration tests for Phase 30 Natural-Language Security Policy Service & Persistence."""

import json
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from analyzer.rules.policy import PolicyEnforcementMode, SecurityPolicy, SecurityPolicyRegistry
from analyzer.rules.policy_authoring import PolicyValidationStatus
from backend.app.db.base import Base
from backend.app.models.triage_feedback import AIPolicyProposalRecord
from backend.app.services.ai.policy_service import NaturalLanguagePolicyService
from backend.app.services.ai.providers.base import LLMResponse


@pytest.fixture
def mock_sql_provider():
    provider = MagicMock()
    sql_candidate = {
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
    provider.generate_sync.return_value = LLMResponse(
        raw_content=json.dumps(sql_candidate),
        parsed_json=sql_candidate,
        model_name="mock-llm",
        provider_name="mock-provider",
        prompt_tokens=150,
        completion_tokens=80,
        latency_ms=45.0,
    )
    return provider


@pytest.fixture
def sqlite_db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_valid_sql_policy_translation(mock_sql_provider):
    """Translates valid parameterization prompt into valid SecurityPolicy candidate."""
    prompt = "All SQL queries originating from HTTP request parameters must use parameterized queries or integer casting."
    status, candidate_dict, diagnostics = NaturalLanguagePolicyService.translate_prompt_to_candidate(
        natural_language_input=prompt,
        provider=mock_sql_provider,
    )

    assert status == PolicyValidationStatus.VALIDATED_CANDIDATE
    assert candidate_dict is not None
    assert candidate_dict["policy_id"] == "POL-SQL-01"
    assert "SQL_EXECUTE" in candidate_dict["target_sink_categories"]
    assert "SQL_PARAMETRIZED" in candidate_dict["required_security_properties"]


def test_ambiguous_prompt_service_rejection():
    """Rejects vague prompts without concrete properties or sinks."""
    prompt = "Make this app secure"
    status, candidate, diagnostics = NaturalLanguagePolicyService.translate_prompt_to_candidate(
        natural_language_input=prompt,
        provider=MagicMock(),
    )
    assert status == PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS
    assert candidate is None
    assert any("Vague" in d for d in diagnostics)


def test_author_and_approve_lifecycle(mock_sql_provider, sqlite_db_session):
    """Verifies complete authoring and human approval lifecycle with registry activation."""
    registry = SecurityPolicyRegistry(load_defaults=False)
    assert registry.get_policy("POL-SQL-01") is None

    prompt = "All SQL execution must be parameterized."
    status, candidate_dto, diags, proposal_record = NaturalLanguagePolicyService.author_policy(
        natural_language_input=prompt,
        author_id="sec-lead@company.com",
        db=sqlite_db_session,
        provider=mock_sql_provider,
    )

    assert status == PolicyValidationStatus.VALIDATED_CANDIDATE
    assert candidate_dto is not None
    assert proposal_record is not None
    assert proposal_record.validation_status == "VALIDATED_CANDIDATE"
    assert proposal_record.approved_at is None

    # Step 2: Human Admin Approval Gate
    activated_policy = NaturalLanguagePolicyService.approve_policy(
        proposal_id=proposal_record.id,
        approved_by="ciso@company.com",
        db=sqlite_db_session,
        registry=registry,
    )

    assert activated_policy is not None
    assert activated_policy.policy_id == "POL-SQL-01"

    # Verify registered in active SecurityPolicyRegistry
    registered = registry.get_policy("POL-SQL-01")
    assert registered is not None
    assert registered.name == "SQL Query Parameterization Policy"
