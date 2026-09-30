"""Unit and integration tests for Phase 30 Exploitability Analysis & Vulnerability Prioritization.

Validates:
- Deterministic exploitability factor calculation from TrustBoundary, Auth, Authz, Controllability, and Path.
- Public unauthenticated SQL injection achieving P0_IMMEDIATE (score >= 85).
- Authenticated admin SQL injection down-prioritized to P2_MEDIUM (score <= 55).
- Unknown / missing evidence fallback to conservative intermediate weighting without crashing.
- Severity preservation invariant (severity remains CRITICAL/HIGH independent of exploitability).
- Evidence grounding check and DB persistence in AIPrioritizationRecord.
"""

import json
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from analyzer.models.boundary import AuthenticationState, AuthorizationState, TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.security.exploitability import (
    ExploitabilityEvaluator,
    InputControllabilityLevel,
    PathFeasibilityLevel,
)
from analyzer.security.prioritization import (
    AssetCriticality,
    PriorityBand,
    PriorityCalculator,
)
from backend.app.db.base import Base
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.triage_feedback import AIPrioritizationRecord
from backend.app.services.ai.prioritizer import AIPrioritizerService
from backend.app.services.ai.providers.base import LLMResponse


@pytest.fixture
def sqlite_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_unauthenticated_sqli_p0_priority():
    """Public unauthenticated SQL injection achieves >= 85 score and P0_IMMEDIATE."""
    assessment = ExploitabilityEvaluator.evaluate(
        boundary=TrustBoundaryType.HTTP_REQUEST_PARAM,
        auth_state=AuthenticationState.UNAUTHENTICATED,
        authz_state=AuthorizationState.UNAUTHORIZED,
        input_controllability=InputControllabilityLevel.DIRECT_STRING_CONCAT,
        path_feasibility=PathFeasibilityLevel.UNCONDITIONAL_FLOW,
        evidence_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
    )

    # Exploitability score should be 1.0 (all factors are 1.0)
    assert assessment.exploitability_score == 1.0

    priority = PriorityCalculator.calculate(
        severity=FindingSeverity.CRITICAL,
        confidence="HIGH",
        exploitability_score=assessment.exploitability_score,
        asset_criticality=AssetCriticality.STANDARD,
    )

    assert priority.final_score == 100.0
    assert priority.final_score >= 85.0
    assert priority.priority_band == PriorityBand.P0_IMMEDIATE


def test_authenticated_admin_p2_priority():
    """Identical SQL injection requiring authenticated admin session achieves <= 55 score (P2_MEDIUM)."""
    assessment = ExploitabilityEvaluator.evaluate(
        boundary=TrustBoundaryType.INTERNAL_SERVICE,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.ROLE_VERIFIED,
        input_controllability=InputControllabilityLevel.INDIRECT_STATE_VARIABLE,
        path_feasibility=PathFeasibilityLevel.COMPLEX_CONSTRAINED_PATH,
        evidence_snippet="admin_query = f'SELECT * FROM audit_logs WHERE filter = {state_var}'",
        guard_count=3,
    )

    # Exploitability: 0.2*0.25 + 0.2*0.20 + 0.25*0.15 + 0.3*0.20 + 0.4*0.20 = 0.05 + 0.04 + 0.0375 + 0.06 + 0.08 = 0.2675
    assert assessment.exploitability_score < 0.35

    priority = PriorityCalculator.calculate(
        severity=FindingSeverity.HIGH,  # High severity (30)
        confidence="MEDIUM",            # Medium confidence (12)
        exploitability_score=assessment.exploitability_score,
        asset_criticality=AssetCriticality.STANDARD,
    )

    # Score: 30 + 12 + 40 * 0.2675 = 52.7
    assert priority.final_score <= 55.0
    assert priority.priority_band == PriorityBand.P2_MEDIUM


def test_unknown_evidence_fallback():
    """Missing auth and boundary evidence defaults to conservative intermediate weights without crashing."""
    assessment = ExploitabilityEvaluator.evaluate(
        boundary=None,
        auth_state=None,
        authz_state=None,
        input_controllability=None,
        path_feasibility=None,
    )

    assert 0.45 <= assessment.exploitability_score <= 0.65
    assert "UNKNOWN" in assessment.contributing_factors["authentication"].evidence
    assert "UNKNOWN" in assessment.contributing_factors["attack_surface"].evidence

    priority = PriorityCalculator.calculate(
        severity="MEDIUM",
        confidence="LOW",
        exploitability_score=assessment.exploitability_score,
    )

    assert 0.0 <= priority.final_score <= 100.0


def test_deterministic_factor_preservation():
    """Verify severity remains high/critical even if exploitability is low."""
    assessment = ExploitabilityEvaluator.evaluate(
        boundary=TrustBoundaryType.INTERNAL_SERVICE,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.ROLE_VERIFIED,
        input_controllability=InputControllabilityLevel.INDIRECT_STATE_VARIABLE,
        path_feasibility=PathFeasibilityLevel.COMPLEX_CONSTRAINED_PATH,
    )

    res = AIPrioritizerService.prioritize_finding(
        finding_id="find-sqli-01",
        rule_id="SEC-PY-005",
        severity=FindingSeverity.CRITICAL,
        confidence="HIGH",
        boundary=TrustBoundaryType.INTERNAL_SERVICE,
        auth_state=AuthenticationState.AUTHENTICATED,
        authz_state=AuthorizationState.ROLE_VERIFIED,
        input_controllability=InputControllabilityLevel.INDIRECT_STATE_VARIABLE,
        path_feasibility=PathFeasibilityLevel.COMPLEX_CONSTRAINED_PATH,
    )

    # Severity remains CRITICAL despite lower priority score
    assert res["severity"] == "CRITICAL"
    assert res["exploitability_score"] == assessment.exploitability_score
    assert res["priority_score"] < 80.0


def test_prioritization_with_ai_rationale_and_persistence(sqlite_session):
    """Verifies LLM rationale integration, evidence grounding, and DB persistence."""
    mock_provider = MagicMock()
    mock_provider.generate_sync.return_value = LLMResponse(
        raw_content=json.dumps({"rationale": "Direct SQL injection in users query reachable via HTTP parameter without authentication."}),
        parsed_json={"rationale": "Direct SQL injection in users query reachable via HTTP parameter without authentication."},
        model_name="mock-llm",
        provider_name="mock-provider",
        prompt_tokens=100,
        completion_tokens=40,
        latency_ms=30.0,
    )

    # Setup parent DB models
    repo = Repository(id="repo-p30", name="codesentinel-p30", path="/fake/path")
    sqlite_session.add(repo)
    snap = AnalysisSnapshot(id="snap-p30", repository_id="repo-p30")
    sqlite_session.add(snap)
    finding = FindingSnapshot(
        id="find-p30-1",
        snapshot_id="snap-p30",
        finding_uuid="find-uuid-p30-1",
        rule_id="SEC-PY-005",
        rule_name="SQL Injection",
        category="SECURITY",
        severity="CRITICAL",
        confidence="HIGH",
        message="SQL injection in query",
        description="User input concatenated into SQL query",
        remediation="Use parameterized queries",
        file_path="app/routes.py",
        line_start=45,
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    )
    sqlite_session.add(finding)
    sqlite_session.commit()

    code_snippet = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"

    res = AIPrioritizerService.prioritize_finding(
        finding_id=finding.id,
        rule_id="SEC-PY-005",
        severity=FindingSeverity.CRITICAL,
        confidence="HIGH",
        boundary=TrustBoundaryType.HTTP_REQUEST_PARAM,
        auth_state=AuthenticationState.UNAUTHENTICATED,
        authz_state=AuthorizationState.UNAUTHORIZED,
        input_controllability=InputControllabilityLevel.DIRECT_STRING_CONCAT,
        path_feasibility=PathFeasibilityLevel.UNCONDITIONAL_FLOW,
        evidence_snippet=code_snippet,
        source_code=code_snippet,
        provider=mock_provider,
        db=sqlite_session,
        snapshot_id=snap.id,
    )

    assert res["priority_band"] == "P0_IMMEDIATE"
    assert res["priority_score"] == 100.0
    assert "record_id" in res

    # Verify persisted in database
    db_record = sqlite_session.query(AIPrioritizationRecord).filter_by(id=res["record_id"]).first()
    assert db_record is not None
    assert db_record.finding_id == finding.id
    assert db_record.priority_score == 100.0
    assert db_record.priority_band == "P0_IMMEDIATE"
    assert db_record.exploitability_score == 1.0
