"""Unit and integration tests for Phase 30 REST API Endpoints and Workspace Scoping.

Tests cover:
- Triage feedback recording via POST /feedback
- On-demand finding prioritization via GET /priority and POST /prioritize
- Natural-language policy authoring and approval via /policies/ai-author and /policies/{id}/approve
- Architectural refactoring proposal listing and simulation rerun
- Cross-repo context scoping respecting FCR boundaries
"""

from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from analyzer.dataflow.contracts.models import FunctionContract, PreconditionKind, SummaryPrecondition
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.boundary import AuthenticationState, AuthorizationState, TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.workspace.ai_context import WorkspaceAIContextScoper
from analyzer.workspace.federated_contracts import FederatedContractRegistry
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.triage_feedback import (
    AIPrioritizationRecord,
    AIRefactoringProposalRecord,
    FindingTriageFeedbackRecord,
)


def test_post_triage_feedback(client_with_db: TestClient, sync_db: Session):
    """POST /feedback records human triage verdict and extracts 18 features."""
    repo = Repository(id="repo-api-1", name="repo-api-1", path="/tmp/repo1")
    sync_db.add(repo)
    snap = AnalysisSnapshot(id="snap-api-1", repository_id="repo-api-1")
    sync_db.add(snap)
    finding = FindingSnapshot(
        id="find-api-1",
        snapshot_id="snap-api-1",
        finding_uuid="uuid-find-1",
        rule_id="SEC-PY-005",
        rule_name="SQL Injection",
        category="SECURITY",
        severity="CRITICAL",
        confidence="HIGH",
        message="SQL injection in routes",
        description="Raw string concat into cursor",
        remediation="Use params",
        file_path="routes/users.py",
        line_start=24,
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    )
    sync_db.add(finding)
    sync_db.commit()

    resp = client_with_db.post(
        f"/api/v1/repositories/{repo.id}/analyses/{snap.id}/findings/{finding.id}/feedback",
        json={
            "label": "FALSE_POSITIVE",
            "reason": "Test fixture with mock constants",
            "reviewer_id": "security-lead@company.com",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["label"] == "FALSE_POSITIVE"
    assert data["features_recorded"] is True
    assert "feedback_id" in data


def test_get_and_post_prioritization(client_with_db: TestClient, sync_db: Session):
    """GET and POST /priority return calculated priority score and band."""
    repo = Repository(id="repo-api-2", name="repo-api-2", path="/tmp/repo2")
    sync_db.add(repo)
    snap = AnalysisSnapshot(id="snap-api-2", repository_id="repo-api-2")
    sync_db.add(snap)
    finding = FindingSnapshot(
        id="find-api-2",
        snapshot_id="snap-api-2",
        finding_uuid="uuid-find-2",
        rule_id="SEC-PY-005",
        rule_name="SQL Injection",
        category="SECURITY",
        severity="CRITICAL",
        confidence="HIGH",
        message="SQL injection in query",
        description="Concatenation",
        remediation="Use params",
        file_path="api/auth.py",
        line_start=30,
        snippet="cursor.execute(f'SELECT * FROM users WHERE name = {name}')",
    )
    sync_db.add(finding)
    sync_db.commit()

    # GET priority
    get_resp = client_with_db.get(
        f"/api/v1/repositories/{repo.id}/analyses/{snap.id}/findings/{finding.id}/priority"
    )
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert "priority_score" in get_data
    assert "priority_band" in get_data

    # POST prioritize
    post_resp = client_with_db.post(
        f"/api/v1/repositories/{repo.id}/analyses/{snap.id}/findings/{finding.id}/prioritize",
        json={"asset_criticality": 1.25},
    )
    assert post_resp.status_code == 200
    post_data = post_resp.json()
    assert post_data["priority_score"] >= 80.0
    assert post_data["priority_band"] == "P0_IMMEDIATE"


def test_policy_studio_author_and_approve(client_with_db: TestClient):
    """Authoring a policy via NL and approving it via API."""
    mock_candidate = {
        "policy_id": "POL-SQL-API-01",
        "name": "SQL Parameterization API Policy",
        "description": "Requires all SQL operations to be parameterized.",
        "source_boundaries": ["HTTP_REQUEST_PARAM"],
        "target_sink_categories": ["SQL_EXECUTE"],
        "required_security_properties": ["SQL_PARAMETRIZED"],
        "allowed_sanitizers": ["int"],
        "require_authentication": True,
        "enforcement_mode": "ENFORCE",
        "severity": "HIGH",
    }

    with patch("backend.app.services.ai.policy_service.NaturalLanguagePolicyService.translate_prompt_to_candidate") as mock_trans:
        from analyzer.rules.policy_authoring import PolicyValidationStatus
        mock_trans.return_value = (PolicyValidationStatus.VALIDATED_CANDIDATE, mock_candidate, ["Valid"])

        # 1. Author policy
        author_resp = client_with_db.post(
            "/api/v1/policies/ai-author",
            json={
                "prompt": "All SQL execution must use parameterization.",
                "author_id": "sec-lead@company.com",
            },
        )
        assert author_resp.status_code == 200
        author_data = author_resp.json()
        assert author_data["validation_status"] == "VALIDATED_CANDIDATE"
        policy_id = author_data["policy_id"]

        # 2. Approve policy
        approve_resp = client_with_db.post(
            f"/api/v1/policies/{policy_id}/approve",
            json={"approved_by": "ciso@company.com"},
        )
        assert approve_resp.status_code == 200
        approve_data = approve_resp.json()
        assert approve_data["status"] == "APPROVED_ACTIVE"
        assert approve_data["approved_by"] == "ciso@company.com"


def test_refactor_proposals_and_simulation(client_with_db: TestClient, sync_db: Session):
    """Listing refactor proposals and executing simulation rerun."""
    repo = Repository(id="repo-api-3", name="repo-api-3", path="/tmp/repo3")
    sync_db.add(repo)
    snap = AnalysisSnapshot(id="snap-api-3", repository_id="repo-api-3")
    sync_db.add(snap)

    proposal_record = AIRefactoringProposalRecord(
        id="prop-api-1",
        snapshot_id=snap.id,
        repository_id=repo.id,
        target_rule_id="ARC-006",
        refactoring_type="CYCLE_BREAKING",
        title="Break component cycle",
        problem_statement="Cycle between comp_a and comp_b",
        proposed_design="Invert dependency",
        affected_components=["comp_a", "comp_b"],
        hypothetical_edge_mutations=[{"action": "REMOVE", "source": "comp_b", "target": "comp_a"}],
        simulated_metric_deltas={"comp_a": {"delta_ca": -1.0}},
        simulation_status="VERIFIED_SIMULATION",
        status="PROPOSAL_ONLY",
        context_hash="hash-prop-1",
    )
    sync_db.add(proposal_record)
    sync_db.commit()

    # GET proposals
    list_resp = client_with_db.get(f"/api/v1/repositories/{repo.id}/analyses/{snap.id}/refactor-proposals")
    assert list_resp.status_code == 200
    proposals = list_resp.json()
    assert len(proposals) == 1
    assert proposals[0]["id"] == "prop-api-1"

    # POST simulate
    sim_resp = client_with_db.post(
        f"/api/v1/repositories/{repo.id}/analyses/{snap.id}/refactor-proposals/prop-api-1/simulate",
        json={"hypothetical_edge_mutations": [{"action": "REMOVE", "source": "comp_b", "target": "comp_a"}]},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["simulation_status"] == "VERIFIED_SIMULATION"
    assert sim_data["target_cycle_eliminated"] is True


def test_workspace_ai_context_fcr_scoping():
    """Verify WorkspaceAIContextScoper isolates private repos and allows only FCR published contracts."""
    fcr = FederatedContractRegistry(workspace_id="test-workspace")

    # Repo B publishes a contract with a sanitizer precondition
    contract_b = FunctionContract(
        qualified_name="auth_lib.sanitize_token",
        file_path="src/sanitize.py",
        is_pure=True,
        preconditions=[
            SummaryPrecondition(
                target_param_index=0,
                target_param_name="token",
                kind=PreconditionKind.SANITIZER_CATEGORY,
                required_sanitizer_category=SinkCategory.SQL_EXECUTE,
            )
        ],
        contract_hash="hash-contract-b",
    )
    fcr.publish_repository_contracts(
        repo_id="repo-b",
        contracts={"sanitize_token": contract_b},
        exported_packages=["auth_lib"],
    )

    # Scoper for Repo A accessing sanitize_token (allowed) and internal_helper (blocked)
    scoped = WorkspaceAIContextScoper.scope_external_references(
        local_repo_id="repo-a",
        fcr=fcr,
        external_symbols=["sanitize_token", "unexported_private_function"],
    )

    assert scoped.boundary_isolation_verified is True
    assert len(scoped.allowed_contracts) == 1
    assert scoped.allowed_contracts[0].symbol_name == "sanitize_token"
    assert scoped.allowed_contracts[0].origin_repo_id == "repo-b"
    assert scoped.allowed_contracts[0].is_pure is True
    assert scoped.allowed_contracts[0].has_sanitizer_effect is True

    # Private/unexported symbol is strictly blocked from AI context
    assert "unexported_private_function" in scoped.blocked_references
