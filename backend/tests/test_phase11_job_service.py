"""Unit tests for JobService business logic, worker dispatch, and cancellation."""

from unittest.mock import MagicMock, patch
import uuid

from fastapi import HTTPException
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.services.job_service import JobService
from backend.tests.conftest import AsyncTestContext


@pytest.mark.asyncio
async def test_job_service_create_and_dispatch(test_ctx: AsyncTestContext):
    """Verify that JobService creates a job, commits before dispatch, and sets celery_task_id."""
    session = await test_ctx.get_session()
    async with session:
        # Create repo
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Dispatch Repo",
            path="/local/dispatch/repo",
        )
        session.add(repo)
        await session.commit()

        # Mock Celery delay
        mock_task = MagicMock()
        mock_task.id = "celery-task-12345"

        with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task) as mock_delay:
            dto = await JobService.create_and_dispatch_job(
                db=session,
                repository_id=repo.id,
                config={"max_component_depth": 2},
            )

            assert dto.id is not None
            assert dto.repository_id == repo.id
            assert dto.status == "QUEUED"
            assert dto.stream_url == f"/api/v1/jobs/{dto.id}/stream"
            mock_delay.assert_called_once_with(str(dto.id))

            # Verify persisted in DB
            persisted = await JobService.get_job(session, dto.id)
            assert persisted is not None
            assert persisted.celery_task_id == "celery-task-12345"


@pytest.mark.asyncio
async def test_job_service_idempotency_guard(test_ctx: AsyncTestContext):
    """Verify that triggering analysis when a job is already active returns the existing job."""
    session = await test_ctx.get_session()
    async with session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Idempotent Repo",
            path="/local/idempotent/repo",
        )
        session.add(repo)
        await session.commit()

        mock_task = MagicMock()
        mock_task.id = "celery-1"

        with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task) as mock_delay:
            job1 = await JobService.create_and_dispatch_job(session, repo.id)
            assert mock_delay.call_count == 1

            # Dispatch again while job1 is still QUEUED
            job2 = await JobService.create_and_dispatch_job(session, repo.id)
            assert job2.id == job1.id
            # Should NOT dispatch a second task
            assert mock_delay.call_count == 1


@pytest.mark.asyncio
async def test_job_service_dispatch_failure_handling(test_ctx: AsyncTestContext):
    """Verify that broker dispatch failure marks the job FAILED and raises 503."""
    session = await test_ctx.get_session()
    async with session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Broker Fail Repo",
            path="/local/fail/repo",
        )
        session.add(repo)
        await session.commit()

        with patch(
            "backend.app.services.job_service.run_analysis_task.delay",
            side_effect=Exception("Redis connection refused"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await JobService.create_and_dispatch_job(session, repo.id)

            assert exc_info.value.status_code == 503

            # Verify job is marked FAILED in DB, not left hanging as QUEUED
            jobs, _ = await JobService.list_jobs(session, repo.id)
            assert len(jobs) == 1
            assert jobs[0].status == "FAILED"
            assert "Redis connection refused" in (jobs[0].error_message or "")


@pytest.mark.asyncio
async def test_job_service_cooperative_cancellation(test_ctx: AsyncTestContext):
    """Verify cooperative cancellation sets Redis flag, updates QUEUED job in DB, and revokes Celery task."""
    session = await test_ctx.get_session()
    async with session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Cancel Repo",
            path="/local/cancel/repo",
        )
        session.add(repo)
        await session.commit()

        mock_task = MagicMock()
        mock_task.id = "celery-to-cancel"

        with patch("backend.app.services.job_service.run_analysis_task.delay", return_value=mock_task):
            job_dto = await JobService.create_and_dispatch_job(session, repo.id)

        with patch("backend.app.services.job_service.ProgressPublisher.request_cancellation") as mock_req_cancel, \
             patch("backend.app.services.job_service.celery_app.control.revoke") as mock_revoke:
            
            cancelled_dto = await JobService.cancel_job(session, job_dto.id)

            assert cancelled_dto.status == "CANCELLED"
            mock_req_cancel.assert_called_once_with(job_dto.id)
            mock_revoke.assert_called_once_with("celery-to-cancel", terminate=False)

            # Check DB state
            job = await JobService.get_job(session, job_dto.id)
            assert job is not None
            assert job.status == "CANCELLED"


@pytest.mark.asyncio
async def test_job_service_list_jobs_pagination(test_ctx: AsyncTestContext):
    """Verify paginated listing of repository jobs."""
    session = await test_ctx.get_session()
    async with session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="List Repo",
            path="/local/list/repo",
        )
        session.add(repo)
        await session.commit()

        for i in range(5):
            job = AnalysisJob(
                id=str(uuid.uuid4()),
                repository_id=repo.id,
                status="COMPLETED" if i % 2 == 0 else "FAILED",
            )
            session.add(job)
        await session.commit()

        items, total = await JobService.list_jobs(session, repo.id, skip=0, limit=3)
        assert total == 5
        assert len(items) == 3

        items2, _ = await JobService.list_jobs(session, repo.id, skip=3, limit=3)
        assert len(items2) == 2
