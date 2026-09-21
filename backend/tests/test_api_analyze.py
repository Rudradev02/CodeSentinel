"""Tests for POST /api/v1/analyze static analysis endpoint."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.analysis import AnalysisResultDTO

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project")


@pytest.fixture
def client():
    """Create test client for FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_analyze_valid_repository(client: TestClient):
    """Verify POST /api/v1/analyze returns 200 with complete AnalysisResultDTO."""
    response = client.post("/api/v1/analyze", json={"path": FIXTURE_PATH})
    assert response.status_code == 200

    data = response.json()
    validated = AnalysisResultDTO.model_validate(data)

    assert validated.status == "COMPLETED"
    assert validated.repository_path == str(Path(FIXTURE_PATH).resolve())
    assert validated.summary.total_findings > 0
    assert len(validated.findings) == validated.summary.total_findings

    # Verify Health Scoring (Phase 7)
    assert validated.health is not None
    assert 0.0 <= validated.health.overall_score <= 100.0
    assert validated.health.overall_grade in ["A", "B", "C", "D", "F"]
    assert validated.health.architecture_health.grade in ["A", "B", "C", "D", "F"]
    assert validated.health.security_posture.grade in ["A", "B", "C", "D", "F"]

    # Verify ComponentGraph
    assert validated.component_graph is not None
    assert len(validated.component_graph.nodes) > 0
    for node in validated.component_graph.nodes:
        assert node.id != ""
        assert 0.0 <= node.coupling.instability <= 1.0

    # Verify Monaco evidence viewer fields
    for finding in validated.findings:
        assert finding.evidence.snippet != ""
        assert finding.evidence.language != ""
        assert len(finding.evidence.highlight_lines) >= 1
        assert finding.location.line_start >= 1


def test_analyze_nonexistent_path_returns_404(client: TestClient):
    """Verify analysis of non-existent directory returns structured 404."""
    response = client.post("/api/v1/analyze", json={"path": "nonexistent_dir_abc_123"})
    assert response.status_code == 404

    data = response.json()
    assert data["code"] == "NOT_FOUND"
    assert "nonexistent_dir_abc_123" in data["message"]


def test_analyze_file_instead_of_dir_returns_400(client: TestClient):
    """Verify analysis of a file path returns structured 400 INVALID_PATH."""
    readme_file = str(Path(__file__).resolve().parent.parent.parent / "README.md")
    response = client.post("/api/v1/analyze", json={"path": readme_file})
    assert response.status_code == 400

    data = response.json()
    assert data["code"] == "INVALID_PATH"
    assert "directory" in data["message"].lower()


def test_analyze_empty_path_returns_400(client: TestClient):
    """Verify empty path string returns 400 INVALID_PATH."""
    response = client.post("/api/v1/analyze", json={"path": "   "})
    assert response.status_code == 400

    data = response.json()
    assert data["code"] == "INVALID_PATH"


def test_analyze_missing_body_field_returns_422(client: TestClient):
    """Verify missing required body fields return structured 422 VALIDATION_ERROR."""
    response = client.post("/api/v1/analyze", json={})
    assert response.status_code == 422

    data = response.json()
    assert data["code"] == "VALIDATION_ERROR"
    assert "details" in data


def test_analyze_determinism(client: TestClient):
    """Verify identical repeated analysis requests produce semantically identical results."""
    resp1 = client.post("/api/v1/analyze", json={"path": FIXTURE_PATH})
    resp2 = client.post("/api/v1/analyze", json={"path": FIXTURE_PATH})

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    data1 = resp1.json()
    data2 = resp2.json()

    # Finding counts and IDs must be deterministic
    assert data1["summary"]["total_findings"] == data2["summary"]["total_findings"]
    finding_ids1 = [f["id"] for f in data1["findings"]]
    finding_ids2 = [f["id"] for f in data2["findings"]]
    assert finding_ids1 == finding_ids2

    # Scores must be identical
    assert data1["health"]["overall_score"] == data2["health"]["overall_score"]
    assert data1["health"]["overall_grade"] == data2["health"]["overall_grade"]

    # Component nodes and ordering must be identical
    nodes1 = [n["id"] for n in data1["component_graph"]["nodes"]]
    nodes2 = [n["id"] for n in data2["component_graph"]["nodes"]]
    assert nodes1 == nodes2
