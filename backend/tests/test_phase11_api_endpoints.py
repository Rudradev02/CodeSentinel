"""Integration tests for Phase 11 REST API endpoints and SSE streaming."""

import json
from unittest.mock import MagicMock, patch
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.tests.conftest import FIXTURE_PATH, AsyncTestContext


def test_post_repository_analyses_returns_202_accepted(client_with_db: TestClient, test_ctx: AsyncTestContext):
    """Verify POST /api/v1/repositories/{id}/analyses dispatches job and returns 202 Accepted."""
    # 1. Register repository
    reg_res = client_with_db.post("/api/v1/repositories", json={"path": FIXTURE_PATH})
    assert reg_res.status_code == 201
    repo_id = reg_res.json()["id"]

    # 2. Trigger analysis with Celery mocked
    mock_task = MagicMock()
    mock_task.id = "celery-mock-id-777"

    with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task):
        res = client_with_db.post(
            f"/api/v1/repositories/{repo_id}/analyses",
            json={"fail_on": "HIGH", "max_component_depth": 2},
        )

        assert res.status_code == 202
        data = res.json()
        assert data["id"] is not None
        assert data["repository_id"] == repo_id
        assert data["status"] == "QUEUED"
        assert data["progress_percent"] == 0
        assert data["stream_url"] == f"/api/v1/jobs/{data['id']}/stream"
        # Invariant: Celery task ID must NOT be exposed to frontend
        assert "celery_task_id" not in data


def test_get_job_status(client_with_db: TestClient, test_ctx: AsyncTestContext):
    """Verify GET /api/v1/jobs/{job_id} returns AnalysisJobDTO and 404 for unknown IDs."""
    reg_res = client_with_db.post("/api/v1/repositories", json={"path": FIXTURE_PATH})
    repo_id = reg_res.json()["id"]

    mock_task = MagicMock()
    mock_task.id = "celery-mock-get"

    with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task):
        post_res = client_with_db.post(f"/api/v1/repositories/{repo_id}/analyses")
        job_id = post_res.json()["id"]

    get_res = client_with_db.get(f"/api/v1/jobs/{job_id}")
    assert get_res.status_code == 200
    job_data = get_res.json()
    assert job_data["id"] == job_id
    assert job_data["status"] == "QUEUED"

    # Test unknown job
    unknown_res = client_with_db.get("/api/v1/jobs/non-existent-uuid")
    assert unknown_res.status_code == 404


def test_post_cancel_job(client_with_db: TestClient, test_ctx: AsyncTestContext):
    """Verify POST /api/v1/jobs/{job_id}/cancel cooperatively cancels an active job."""
    reg_res = client_with_db.post("/api/v1/repositories", json={"path": FIXTURE_PATH})
    repo_id = reg_res.json()["id"]

    mock_task = MagicMock()
    mock_task.id = "celery-mock-cancel"

    with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task):
        post_res = client_with_db.post(f"/api/v1/repositories/{repo_id}/analyses")
        job_id = post_res.json()["id"]

    with patch("backend.app.services.job_service.ProgressPublisher.request_cancellation"), \
         patch("backend.app.services.job_service.celery_app.control.revoke"):
        
        cancel_res = client_with_db.post(f"/api/v1/jobs/{job_id}/cancel")
        assert cancel_res.status_code == 200
        cancel_data = cancel_res.json()
        assert cancel_data["id"] == job_id
        assert cancel_data["status"] == "CANCELLED"

    # Verify subsequent GET returns CANCELLED
    check_res = client_with_db.get(f"/api/v1/jobs/{job_id}")
    assert check_res.json()["status"] == "CANCELLED"


def test_get_repository_jobs_paginated(client_with_db: TestClient, test_ctx: AsyncTestContext):
    """Verify GET /api/v1/repositories/{id}/jobs returns paginated job list."""
    reg_res = client_with_db.post("/api/v1/repositories", json={"path": FIXTURE_PATH})
    repo_id = reg_res.json()["id"]

    # Direct insert jobs
    sync_session = test_ctx.get_sync_session()
    for i in range(3):
        sync_session.add(
            AnalysisJob(
                id=str(uuid.uuid4()),
                repository_id=repo_id,
                status="COMPLETED",
            )
        )
    sync_session.commit()
    sync_session.close()

    res = client_with_db.get(f"/api/v1/repositories/{repo_id}/jobs?skip=0&limit=2")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2


def test_sse_stream_initial_terminal_state(client_with_db: TestClient, test_ctx: AsyncTestContext):
    """Verify GET /api/v1/jobs/{id}/stream emits initial state and closes immediately if job is terminal."""
    reg_res = client_with_db.post("/api/v1/repositories", json={"path": FIXTURE_PATH})
    repo_id = reg_res.json()["id"]

    # Insert a COMPLETED job
    job_id = str(uuid.uuid4())
    sync_session = test_ctx.get_sync_session()
    sync_session.add(
        AnalysisJob(
            id=job_id,
            repository_id=repo_id,
            status="COMPLETED",
            progress_percent=100,
            snapshot_id="snapshot-12345",
        )
    )
    sync_session.commit()
    sync_session.close()

    # Stream should yield completed event and close
    with client_with_db.stream("GET", f"/api/v1/jobs/{job_id}/stream") as response:
        assert response.status_code == 200
        content = ""
        for line in response.iter_lines():
            content += line + "\n"

        assert "event: completed" in content
        assert "snapshot-12345" in content
