"""Tests for GET /api/v1/rules metadata endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.rules import RuleListResponse, RuleMetadataDTO


@pytest.fixture
def client():
    """Create test client for FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_list_rules_endpoint(client: TestClient):
    """Verify GET /api/v1/rules returns all registered rules sorted by rule_id."""
    response = client.get("/api/v1/rules")
    assert response.status_code == 200

    data = response.json()
    validated = RuleListResponse.model_validate(data)
    assert validated.total_rules > 0
    assert len(validated.rules) == validated.total_rules

    # Verify deterministic sorting by rule_id
    rule_ids = [r.rule_id for r in validated.rules]
    assert rule_ids == sorted(rule_ids)

    # Check known rules exist
    assert "ARC-001" in rule_ids
    assert "ARC-005" in rule_ids
    assert "ARC-006" in rule_ids
    assert "SEC-PY-001" in rule_ids


def test_get_rule_detail_valid(client: TestClient):
    """Verify GET /api/v1/rules/{rule_id} returns rule details."""
    response = client.get("/api/v1/rules/ARC-005")
    assert response.status_code == 200

    data = response.json()
    validated = RuleMetadataDTO.model_validate(data)
    assert validated.rule_id == "ARC-005"
    assert validated.category == "ARCHITECTURE"
    assert validated.name != ""
    assert validated.description != ""


def test_get_rule_detail_case_insensitive(client: TestClient):
    """Verify rule lookup is case-insensitive."""
    response = client.get("/api/v1/rules/arc-005")
    assert response.status_code == 200
    assert response.json()["rule_id"] == "ARC-005"


def test_get_rule_unknown_returns_404(client: TestClient):
    """Verify GET /api/v1/rules/{rule_id} with unknown rule returns structured 404."""
    response = client.get("/api/v1/rules/NONEXISTENT_RULE_999")
    assert response.status_code == 404

    data = response.json()
    assert data["code"] == "RULE_NOT_FOUND"
    assert "NONEXISTENT_RULE_999" in data["message"]
