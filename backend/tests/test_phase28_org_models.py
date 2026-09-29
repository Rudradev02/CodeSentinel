"""Unit tests for Phase 28 Organization, Workspace, and Central Policy ORM models."""

from datetime import datetime, timedelta, timezone
import pytest

from backend.app.models.organization import Organization
from backend.app.models.policy import CentralizedRulePack, CentralizedSuppression
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.workspace import Workspace, WorkspaceRepository, WorkspaceSnapshot
from backend.app.schemas.analysis import AnalysisResultDTO


class TestOrganizationAndWorkspaceModels:
    """Tests for multi-repository organization hierarchy."""

    def test_organization_creation(self):
        org = Organization(
            id="org-acme-1",
            name="Acme Financial Technologies",
            slug="acme-fintech",
        )
        assert org.id == "org-acme-1"
        assert org.name == "Acme Financial Technologies"
        assert org.slug == "acme-fintech"
        assert "acme-fintech" in repr(org)

    def test_workspace_and_repository_link(self):
        ws = Workspace(
            id="ws-pay-1",
            organization_id="org-acme-1",
            name="Payment Processing Fleet",
            slug="payment-fleet",
            manifest_path="/workspaces/payment-fleet/codesentinel-workspace.yaml",
            config_payload={"cross_repo_taint_depth": 4},
        )
        assert ws.slug == "payment-fleet"
        assert ws.config_payload["cross_repo_taint_depth"] == 4

        link = WorkspaceRepository(
            workspace_id=ws.id,
            repository_id="repo-gateway-1",
            role="PUBLIC_ENTRYPOINT",
            criticality="CRITICAL",
            depends_on=["repo-auth-1", "repo-db-1"],
        )
        assert link.workspace_id == "ws-pay-1"
        assert link.role == "PUBLIC_ENTRYPOINT"
        assert link.criticality == "CRITICAL"
        assert len(link.depends_on) == 2

    def test_workspace_snapshot_and_analysis_link(self):
        ws_snap = WorkspaceSnapshot(
            id="ws-snap-101",
            workspace_id="ws-pay-1",
            composite_health_score=88.5,
            composite_grade="B",
            total_findings=5,
            critical_findings=0,
            high_findings=2,
            merkle_workspace_root="a" * 64,
            repository_snapshot_ids=["snap-repo-1", "snap-repo-2"],
        )
        assert ws_snap.composite_grade == "B"
        assert len(ws_snap.merkle_workspace_root) == 64

        analysis_snap = AnalysisSnapshot(
            id="snap-repo-1",
            repository_id="repo-gateway-1",
            workspace_snapshot_id=ws_snap.id,
            compliance_suite={"overall_score": 92.0},
            attestation_envelope={"payload": "eyJ..."},
        )
        assert analysis_snap.workspace_snapshot_id == "ws-snap-101"
        assert analysis_snap.compliance_suite["overall_score"] == 92.0
        assert analysis_snap.attestation_envelope["payload"] == "eyJ..."

    def test_centralized_rule_pack_model(self):
        pack = CentralizedRulePack(
            id="crp-1",
            organization_id="org-acme-1",
            pack_id="pci-dss-v4",
            version="1.2.0",
            name="PCI DSS v4 Enterprise Baseline",
            pack_yaml="pack_id: pci-dss-v4\nallow_repo_override: false",
            pack_hash="b" * 64,
        )
        assert pack.pack_id == "pci-dss-v4"
        assert len(pack.pack_hash) == 64
        assert "pci-dss-v4" in repr(pack)

    def test_centralized_suppression_expiration(self):
        now = datetime.now(timezone.utc)
        active_supp = CentralizedSuppression(
            id="supp-active",
            organization_id="org-acme-1",
            rule_id="SEC-PY-001",
            target_repo_id="repo-gateway-1",
            justification="Test credential in mock fixture",
            compensating_control="Mock vault active",
            approved_by="sec-team@acme.com",
            ticket_reference="SEC-1001",
            expires_at=now + timedelta(days=30),
        )
        assert active_supp.is_expired is False

        expired_supp = CentralizedSuppression(
            id="supp-expired",
            organization_id="org-acme-1",
            rule_id="SEC-PY-002",
            target_repo_id="*",
            justification="Temporary deferral",
            compensating_control="WAF regex filter",
            approved_by="lead@acme.com",
            ticket_reference="SEC-999",
            expires_at=now - timedelta(days=1),
        )
        assert expired_supp.is_expired is True
