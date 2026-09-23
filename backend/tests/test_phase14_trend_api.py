"""Tests for Phase 14 Trend API endpoint GET /api/v1/repositories/{id}/trends."""

from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.schemas.trend import LongitudinalTrendDTO

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project")


def test_get_trends_nonexistent_repository(client_with_db: TestClient):
    """Querying trends for nonexistent repository returns 404."""
    response = client_with_db.get("/api/v1/repositories/nonexistent-uuid-12345/trends")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()


def test_get_trends_empty_repository(client_with_db: TestClient):
    """Newly registered repository with zero snapshots returns 200 with empty trajectories."""
    reg_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "Trends API Empty Repo"},
    )
    assert reg_res.status_code == 201
    repo_id = reg_res.json()["id"]

    trend_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/trends")
    assert trend_res.status_code == 200
    dto = LongitudinalTrendDTO.model_validate(trend_res.json())

    assert dto.repository_id == repo_id
    assert dto.total_snapshots == 0
    assert dto.health_trajectory == []
    assert dto.defect_velocity == []
    assert dto.overall_health_delta == 0.0


def test_get_trends_with_query_parameters(client_with_db: TestClient):
    """Endpoint respects branch, days, and limit query parameters."""
    reg_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "Trends Query Repo"},
    )
    assert reg_res.status_code == 201
    repo_id = reg_res.json()["id"]

    trend_res = client_with_db.get(
        f"/api/v1/repositories/{repo_id}/trends?branch=main&days=30&limit=10"
    )
    assert trend_res.status_code == 200
    dto = LongitudinalTrendDTO.model_validate(trend_res.json())

    assert dto.repository_id == repo_id
    assert dto.branch == "main"
    assert dto.window_days == 30
