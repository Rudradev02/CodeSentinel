"""Integration tests for Phase 28 REST API endpoints (Organizations & Workspaces)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import uuid
import pytest
from fastapi.testclient import TestClient


SAMPLE_RULE_PACK_YAML = """
pack_id: "org-pci-baseline"
version: "1.0.0"
name: "Organizational PCI Baseline"
description: "Enterprise enforced security baseline"
allow_repo_override: false
rule_overrides:
  - rule_id: "SEC-PY-001"
    enabled: true
    severity: "CRITICAL"
"""


def test_organization_crud_api(client_with_db: TestClient):
    """Test creating, listing, and getting organization details."""
    org_name = f"Acme Corp {uuid.uuid4().hex[:6]}"
    # 1. Create Organization
    res = client_with_db.post("/api/v1/organizations", json={"name": org_name})
    assert res.status_code == 201
    data = res.json()
    org_id = data["id"]
    assert data["name"] == org_name
    assert "slug" in data

    # 2. List Organizations
    list_res = client_with_db.get("/api/v1/organizations")
    assert list_res.status_code == 200
    org_list = list_res.json()
    assert any(o["id"] == org_id for o in org_list)

    # 3. Get Organization Details
    detail_res = client_with_db.get(f"/api/v1/organizations/{org_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == org_id
    assert detail["workspace_count"] == 0
    assert detail["rule_pack_count"] == 0


def test_workspace_crud_and_topology_api(client_with_db: TestClient, tmp_path: Path):
    """Test creating a workspace and inspecting DAG execution waves."""
    # 1. Create Org
    org_res = client_with_db.post("/api/v1/organizations", json={"name": "Fintech Global"})
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    # 2. Register Repos with real disk paths
    p1 = tmp_path / "auth_svc"
    p1.mkdir()
    p2 = tmp_path / "pay_gw"
    p2.mkdir()

    r1 = client_with_db.post("/api/v1/repositories", json={"path": str(p1), "name": "auth-service"}).json()
    r2 = client_with_db.post("/api/v1/repositories", json={"path": str(p2), "name": "payment-gateway"}).json()

    # 3. Create Workspace with dependency: payment-gateway depends on auth-service
    ws_payload = {
        "name": "Payments System",
        "manifest_path": str(tmp_path / "codesentinel-workspace.yaml"),
        "repositories": [
            {
                "repository_id": r1["id"],
                "role": "INTERNAL_LIBRARY",
                "criticality": "HIGH",
                "depends_on": [],
            },
            {
                "repository_id": r2["id"],
                "role": "PUBLIC_ENTRYPOINT",
                "criticality": "CRITICAL",
                "depends_on": [r1["id"]],
            },
        ],
    }
    ws_res = client_with_db.post(f"/api/v1/organizations/{org_id}/workspaces", json=ws_payload)
    assert ws_res.status_code == 201
    ws_data = ws_res.json()
    ws_id = ws_data["id"]
    assert ws_data["organization_id"] == org_id

    # 4. Get Workspace Details & Topology
    detail_res = client_with_db.get(f"/api/v1/workspaces/{ws_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["repositories"]) == 2
    assert len(detail["execution_waves"]) == 2
    # Wave 0 must be r1, Wave 1 must be r2
    assert detail["execution_waves"][0] == [r1["id"]]
    assert detail["execution_waves"][1] == [r2["id"]]


def test_central_rule_pack_and_suppression_api(client_with_db: TestClient):
    """Test registering central rule packs and suppressions via API."""
    org_res = client_with_db.post("/api/v1/organizations", json={"name": "Compliance Core"})
    org_id = org_res.json()["id"]

    # 1. Register Rule Pack
    rp_res = client_with_db.post(
        f"/api/v1/organizations/{org_id}/rule-packs",
        json={
            "pack_id": "org-pci-baseline",
            "version": "1.0.0",
            "pack_yaml": SAMPLE_RULE_PACK_YAML,
        },
    )
    assert rp_res.status_code == 201
    rp_data = rp_res.json()
    assert rp_data["pack_id"] == "org-pci-baseline"
    assert rp_data["pack_hash"] != ""

    # 2. List Rule Packs
    list_rp = client_with_db.get(f"/api/v1/organizations/{org_id}/rule-packs")
    assert list_rp.status_code == 200
    assert len(list_rp.json()) == 1

    # 3. Create Suppression
    expiry = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
    supp_res = client_with_db.post(
        f"/api/v1/organizations/{org_id}/suppressions",
        json={
            "rule_id": "SEC-PY-001",
            "target_repo_id": "*",
            "justification": "Compensating AWS WAF rule active at gateway",
            "compensating_control": "AWS WAF Rule #4401 regex filter",
            "approved_by": "ciso@company.com",
            "ticket_reference": "SEC-9012",
            "expires_at": expiry,
        },
    )
    assert supp_res.status_code == 201
    supp_data = supp_res.json()
    assert supp_data["rule_id"] == "SEC-PY-001"
    assert supp_data["ticket_reference"] == "SEC-9012"

    # 4. List Suppressions
    list_supp = client_with_db.get(f"/api/v1/organizations/{org_id}/suppressions")
    assert list_supp.status_code == 200
    assert len(list_supp.json()) == 1


def test_workspace_scan_trigger_and_snapshots_api(client_with_db: TestClient):
    """Test enqueueing workspace scan and listing historical snapshots."""
    org_res = client_with_db.post("/api/v1/organizations", json={"name": "Fleet Corp"})
    org_id = org_res.json()["id"]

    ws_res = client_with_db.post(
        f"/api/v1/organizations/{org_id}/workspaces",
        json={"name": "Fleet Workspace", "manifest_path": "./dummy.yaml"},
    )
    ws_id = ws_res.json()["id"]

    # Trigger scan with mocked task
    mock_task = MagicMock()
    mock_task.id = "workspace-task-999"
    with patch("backend.app.api.v1.endpoints.workspaces.run_workspace_scan_task.delay", return_value=mock_task):
        scan_res = client_with_db.post(f"/api/v1/workspaces/{ws_id}/scan")
        assert scan_res.status_code == 202
        assert scan_res.json()["status"] == "ACCEPTED"
        assert scan_res.json()["task_id"] == "workspace-task-999"

    # List snapshots (empty initially)
    snaps_res = client_with_db.get(f"/api/v1/workspaces/{ws_id}/snapshots")
    assert snaps_res.status_code == 200
    assert isinstance(snaps_res.json(), list)
