"""Tests for Phase 10 REST API endpoints: Repositories, Analyses, and History."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.schemas.analysis import AnalysisResultDTO
from backend.app.schemas.repository import AnalysisHistoryResponse, RepositoryListResponse, RepositoryResponse

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project")


def test_register_repository_success(client_with_db: TestClient):
    """Verify POST /api/v1/repositories registers a valid directory path."""
    response = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "Sample Test Repo"},
    )
    assert response.status_code == 201
    data = response.json()
    repo = RepositoryResponse.model_validate(data)

    assert repo.name == "Sample Test Repo"
    assert repo.path == str(Path(FIXTURE_PATH).resolve())
    assert repo.analysis_count == 0


def test_register_repository_security_violations(client_with_db: TestClient):
    """Verify security boundary enforcement during repository registration."""
    # 1. Nonexistent path -> 404
    res_nonexistent = client_with_db.post(
        "/api/v1/repositories",
        json={"path": "C:\\nonexistent\\repo\\path"},
    )
    assert res_nonexistent.status_code == 404

    # 2. File instead of directory -> 400
    file_path = str(Path(FIXTURE_PATH) / "backend" / "models" / "user.py")
    res_file = client_with_db.post(
        "/api/v1/repositories",
        json={"path": file_path},
    )
    assert res_file.status_code == 400

    # 3. Drive root -> 403
    res_root = client_with_db.post(
        "/api/v1/repositories",
        json={"path": "C:\\"},
    )
    assert res_root.status_code == 403


def test_list_and_get_repositories(client_with_db: TestClient):
    """Verify GET /api/v1/repositories and GET /api/v1/repositories/{id}."""
    # Register repository
    create_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "List Test Repo"},
    )
    repo_id = create_res.json()["id"]

    # List
    list_res = client_with_db.get("/api/v1/repositories?skip=0&limit=10")
    assert list_res.status_code == 200
    list_data = RepositoryListResponse.model_validate(list_res.json())
    assert list_data.total >= 1
    assert any(r.id == repo_id for r in list_data.items)

    # Get single
    get_res = client_with_db.get(f"/api/v1/repositories/{repo_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == repo_id

    # Get unknown -> 404
    bad_res = client_with_db.get("/api/v1/repositories/00000000-0000-0000-0000-000000000000")
    assert bad_res.status_code == 404


import json
from analyzer.engine.pipeline import AnalysisPipeline


def test_run_analysis_and_retrieve_history(client_with_db: TestClient):
    """Verify POST /api/v1/repositories/{id}/snapshots stores immutable snapshot and allows retrieval."""
    # 1. Register repo
    create_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "Analyze Test Repo"},
    )
    repo_id = create_res.json()["id"]

    # 2. Ingest analysis snapshot
    pipeline = AnalysisPipeline()
    result = pipeline.run(Path(FIXTURE_PATH))
    run_res = client_with_db.post(
        f"/api/v1/repositories/{repo_id}/snapshots",
        json=json.loads(result.model_dump_json()),
    )
    assert run_res.status_code == 201
    result_data = run_res.json()
    validated = AnalysisResultDTO.model_validate(result_data)
    assert validated.status == "COMPLETED"
    assert validated.summary.total_findings > 0
    analysis_id = validated.id

    # 3. Retrieve analysis history
    history_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses")
    assert history_res.status_code == 200
    history = AnalysisHistoryResponse.model_validate(history_res.json())
    assert history.total == 1
    assert history.items[0].id == analysis_id
    assert history.items[0].overall_score == validated.health.overall_score

    # 4. Fetch specific historical analysis
    detail_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses/{analysis_id}")
    assert detail_res.status_code == 200
    historical_dto = AnalysisResultDTO.model_validate(detail_res.json())
    assert historical_dto.id == analysis_id
    assert historical_dto.health.overall_score == validated.health.overall_score
    assert len(historical_dto.findings) == len(validated.findings)


def test_api_repository_isolation_enforcement(client_with_db: TestClient):
    """Verify API prevents accessing Repo B's analysis using Repo A's endpoint."""
    res_a = client_with_db.post(
        "/api/v1/repositories",
        json={"path": str(Path(FIXTURE_PATH) / "backend"), "name": "Repo A"},
    )
    repo_a_id = res_a.json()["id"]

    res_b = client_with_db.post(
        "/api/v1/repositories",
        json={"path": str(Path(FIXTURE_PATH) / "frontend"), "name": "Repo B"},
    )
    repo_b_id = res_b.json()["id"]

    # Ingest analysis for Repo B
    pipeline = AnalysisPipeline()
    result_b = pipeline.run(Path(FIXTURE_PATH) / "frontend")
    run_b = client_with_db.post(
        f"/api/v1/repositories/{repo_b_id}/snapshots",
        json=json.loads(result_b.model_dump_json()),
    )
    assert run_b.status_code == 201
    analysis_b_id = run_b.json()["id"]

    # Attempt to fetch Repo B's analysis under Repo A -> MUST return 404
    leak_attempt = client_with_db.get(f"/api/v1/repositories/{repo_a_id}/analyses/{analysis_b_id}")
    assert leak_attempt.status_code == 404


def test_delete_repository_cascades(client_with_db: TestClient):
    """Verify DELETE /api/v1/repositories/{id} removes repository and cascaded analyses."""
    create_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": FIXTURE_PATH, "name": "Delete Test Repo"},
    )
    repo_id = create_res.json()["id"]

    # Ingest analysis
    pipeline = AnalysisPipeline()
    result = pipeline.run(Path(FIXTURE_PATH))
    client_with_db.post(
        f"/api/v1/repositories/{repo_id}/snapshots",
        json=json.loads(result.model_dump_json()),
    )

    # Delete repository
    del_res = client_with_db.delete(f"/api/v1/repositories/{repo_id}")
    assert del_res.status_code == 204

    # Subsequent GET returns 404
    assert client_with_db.get(f"/api/v1/repositories/{repo_id}").status_code == 404
    assert client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses").status_code == 404

