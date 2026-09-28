"""Tests for Phase 26 backend compliance endpoints and API backward compatibility."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from analyzer.compliance.attestation import (
    AttestationPredicate,
    ScanAttestationStatement,
    sign_attestation,
)

client = TestClient(app)


def test_list_compliance_frameworks_endpoint():
    """Verify GET /api/v1/compliance/frameworks returns supported frameworks."""
    response = client.get("/api/v1/compliance/frameworks")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 4
    fw_ids = [item["framework_id"] for item in data]
    assert "PCI_DSS_V4_0" in fw_ids
    assert "HIPAA_SECURITY" in fw_ids


def test_get_framework_controls_endpoint():
    """Verify GET /api/v1/compliance/frameworks/{id}/controls returns control items."""
    response = client.get("/api/v1/compliance/frameworks/PCI_DSS_V4_0/controls")
    assert response.status_code == 200
    controls = response.json()
    assert len(controls) > 0
    c_ids = [c["control_id"] for c in controls]
    assert "PCI-6.2.4" in c_ids

    # Not found case
    err_resp = client.get("/api/v1/compliance/frameworks/UNKNOWN_FW/controls")
    assert err_resp.status_code == 404


def test_list_rule_packs_endpoint():
    """Verify GET /api/v1/compliance/packs returns registered packs."""
    response = client.get("/api/v1/compliance/packs")
    assert response.status_code == 200
    packs = response.json()
    assert len(packs) > 0
    pack_ids = [p["pack_id"] for p in packs]
    assert "pci-dss-v4" in pack_ids or "hipaa-security" in pack_ids


def test_verify_attestation_api_endpoint():
    """Verify POST /api/v1/compliance/verify-attestation endpoint."""
    predicate = AttestationPredicate(
        tool_name="CodeSentinel",
        tool_version="0.1.0",
        analysis_timestamp="2026-09-28T12:00:00Z",
        config_fingerprint="cfg123",
        findings_merkle_root="root123",
        suppressions_digest="",
    )
    stmt = ScanAttestationStatement(subject=[], predicate=predicate)
    secret = "test-api-secret-key"
    env = sign_attestation(stmt, secret)

    # Valid verification
    payload = {
        "payload": env.payload,
        "payloadType": env.payloadType,
        "signatures": env.signatures,
        "secret_key": secret,
    }
    resp = client.post("/api/v1/compliance/verify-attestation", json=payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["is_valid"] is True
    assert res_data["statement"] is not None

    # Invalid verification
    bad_payload = dict(payload, secret_key="wrong-key")
    bad_resp = client.post("/api/v1/compliance/verify-attestation", json=bad_payload)
    assert bad_resp.status_code == 200
    assert bad_resp.json()["is_valid"] is False
