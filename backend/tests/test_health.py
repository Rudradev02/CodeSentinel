"""Tests for backend health endpoints and startup behavior."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.health import HealthResponse


@pytest.fixture
def client():
    """Create test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_root_health_endpoint(client: TestClient):
    """Verify GET /health returns 200 and conforms to HealthResponse schema."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    # Validate against Pydantic schema
    validated = HealthResponse.model_validate(data)

    assert validated.status == "healthy"
    assert validated.service == "CodeSentinel API"
    assert validated.version == "0.1.0"
    assert validated.uptime_seconds >= 0.0
    assert validated.components["api"] == "healthy"
    assert "available" in validated.components["analyzer_engine"]
    assert "not_configured" in validated.components["database"]
    assert "not_configured" in validated.components["redis_queue"]


def test_v1_health_endpoint(client: TestClient):
    """Verify GET /api/v1/health returns 200 and matches expected structure."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    validated = HealthResponse.model_validate(data)

    assert validated.status == "healthy"
    assert validated.service == "CodeSentinel API"
    assert validated.environment in ["development", "production", "test"]
    assert validated.components["api"] == "healthy"


def test_openapi_docs_available(client: TestClient):
    """Verify that OpenAPI spec and Swagger docs load cleanly."""
    res_openapi = client.get("/openapi.json")
    assert res_openapi.status_code == 200
    spec = res_openapi.json()
    assert spec["info"]["title"] == "CodeSentinel API"

    res_docs = client.get("/docs")
    assert res_docs.status_code == 200
