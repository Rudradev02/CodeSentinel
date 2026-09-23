"""Unit tests for Celery worker analysis task execution in synchronous DB context."""

from unittest.mock import MagicMock, patch
import uuid

import pytest
from sqlalchemy.orm import Session

from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.services.progress import ProgressPublisher
from backend.app.workers.tasks import run_analysis_task
from backend.tests.conftest import FIXTURE_PATH, AsyncTestContext


def test_worker_run_analysis_task_success(test_ctx: AsyncTestContext, sync_db: Session):
    """Verify that worker executes analysis, emits progress, persists snapshot, and completes."""
    # 1. Create registered repository pointing to test fixture
    repo = Repository(
        id=str(uuid.uuid4()),
        name="Worker Test Repo",
        path=FIXTURE_PATH,
    )
    sync_db.add(repo)
    sync_db.commit()

    # 2. Create job
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        status="QUEUED",
        configuration={"fail_on": "CRITICAL"},
    )
    sync_db.add(job)
    sync_db.commit()

    # 3. Patch get_sync_db so the worker uses test_ctx's sync session
    from contextlib import contextmanager
    @contextmanager
    def sync_db_cm(database_url=None):
        yield sync_db

    with patch("backend.app.workers.tasks.get_sync_db", side_effect=sync_db_cm), \
         patch("backend.app.services.progress.get_redis_client") as mock_redis, \
         patch("backend.app.services.cache.get_redis_client") as mock_cache_redis:

        # Mock Redis publish
        mock_redis.return_value = MagicMock()
        mock_cache_redis.return_value = MagicMock()

        # Run task synchronously via Celery's apply()
        res = run_analysis_task.apply(args=[job.id], task_id="task-worker-test-1").result

        assert res["status"] == "COMPLETED"
        assert res["snapshot_id"] is not None

        # Verify job in DB
        sync_db.expire_all()
        completed_job = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
        assert completed_job is not None
        assert completed_job.status == "COMPLETED"
        assert completed_job.progress_percent == 100
        assert completed_job.snapshot_id == res["snapshot_id"]
        assert completed_job.celery_task_id == "task-worker-test-1"

        # Verify snapshot and related findings exist
        snapshot = sync_db.query(AnalysisSnapshot).filter_by(id=res["snapshot_id"]).first()
        assert snapshot is not None
        assert snapshot.repository_id == repo.id
        assert len(snapshot.findings) > 0


def test_worker_cooperative_cancellation_handling(test_ctx: AsyncTestContext, sync_db: Session):
    """Verify that worker respects cooperative cancellation flag and marks job CANCELLED."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="Worker Cancel Repo",
        path=FIXTURE_PATH,
    )
    sync_db.add(repo)
    sync_db.commit()

    job = AnalysisJob(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        status="QUEUED",
    )
    sync_db.add(job)
    sync_db.commit()

    from contextlib import contextmanager
    @contextmanager
    def sync_db_cm(database_url=None):
        yield sync_db

    with patch("backend.app.workers.tasks.get_sync_db", side_effect=sync_db_cm), \
         patch("backend.app.workers.tasks.ProgressPublisher.is_cancelled", return_value=True), \
         patch("backend.app.workers.tasks.ProgressPublisher.publish_progress"):

        res = run_analysis_task.apply(args=[job.id], task_id="task-cancel-test").result
        assert res["status"] == "CANCELLED"

        sync_db.expire_all()
        cancelled_job = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
        assert cancelled_job.status == "CANCELLED"


def test_worker_missing_repository_handling(test_ctx: AsyncTestContext, sync_db: Session):
    """Verify that worker sets job status to FAILED if repository does not exist."""
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        repository_id="non-existent-repo-id",
        status="QUEUED",
    )
    sync_db.add(job)
    sync_db.commit()

    from contextlib import contextmanager
    @contextmanager
    def sync_db_cm(database_url=None):
        yield sync_db

    with patch("backend.app.workers.tasks.get_sync_db", side_effect=sync_db_cm), \
         patch("backend.app.workers.tasks.ProgressPublisher.publish_progress"):

        res = run_analysis_task.apply(args=[job.id], task_id="task-fail-test").result
        assert res["status"] == "FAILED"

        sync_db.expire_all()
        failed_job = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
        assert failed_job.status == "FAILED"
        assert "not found" in (failed_job.error_message or "")
