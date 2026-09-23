"""Unit tests for AnalysisJob ORM model."""

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot


def test_analysis_job_creation_defaults(sync_db: Session):
    """Verify that AnalysisJob defaults are properly initialized."""
    # 1. Create parent repository
    repo = Repository(
        id=str(uuid.uuid4()),
        name="Test Repo",
        path="/local/test/repo",
    )
    sync_db.add(repo)
    sync_db.commit()

    # 2. Create job
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
    )
    sync_db.add(job)
    sync_db.commit()

    # 3. Verify defaults
    queried = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
    assert queried is not None
    assert queried.repository_id == repo.id
    assert queried.status == "QUEUED"
    assert queried.progress_percent == 0
    assert queried.celery_task_id is None
    assert queried.snapshot_id is None
    assert queried.started_at is None
    assert queried.completed_at is None
    assert isinstance(queried.created_at, datetime)


def test_analysis_job_status_lifecycle_updates(sync_db: Session):
    """Verify lifecycle status transitions: QUEUED -> RUNNING -> COMPLETED."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="Lifecycle Repo",
        path="/local/lifecycle/repo",
    )
    sync_db.add(repo)
    sync_db.commit()

    job = AnalysisJob(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        configuration={"fail_on": "HIGH", "max_component_depth": 3},
    )
    sync_db.add(job)
    sync_db.commit()

    # Transition to RUNNING
    job.status = "RUNNING"
    job.started_at = datetime.now(timezone.utc)
    job.progress_percent = 45
    job.progress_stage = "PARSING"
    job.progress_message = "Parsing syntax trees..."
    sync_db.commit()

    updated = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
    assert updated.status == "RUNNING"
    assert updated.progress_percent == 45
    assert updated.progress_stage == "PARSING"
    assert updated.configuration["fail_on"] == "HIGH"

    # Transition to COMPLETED with snapshot
    dummy_snapshot = AnalysisSnapshot(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        created_at=datetime.now(timezone.utc),
        analyzer_version="0.1.0",
        status="COMPLETED",
    )
    sync_db.add(dummy_snapshot)
    sync_db.commit()

    job.status = "COMPLETED"
    job.snapshot_id = dummy_snapshot.id
    job.completed_at = datetime.now(timezone.utc)
    job.progress_percent = 100
    job.progress_stage = "COMPLETED"
    sync_db.commit()

    final_job = sync_db.query(AnalysisJob).filter_by(id=job.id).first()
    assert final_job.status == "COMPLETED"
    assert final_job.snapshot_id == dummy_snapshot.id
    assert final_job.progress_percent == 100
    assert final_job.snapshot.id == dummy_snapshot.id


def test_repository_jobs_relationship_and_cascade_delete(sync_db: Session):
    """Verify that deleting a repository cascades and removes its analysis jobs."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="Cascade Repo",
        path="/local/cascade/repo",
    )
    sync_db.add(repo)
    sync_db.commit()

    job1 = AnalysisJob(id=str(uuid.uuid4()), repository_id=repo.id, status="COMPLETED")
    job2 = AnalysisJob(id=str(uuid.uuid4()), repository_id=repo.id, status="FAILED")
    sync_db.add_all([job1, job2])
    sync_db.commit()

    # Check relationship
    sync_db.refresh(repo)
    assert len(repo.jobs) == 2

    # Delete repository
    sync_db.delete(repo)
    sync_db.commit()

    # Jobs must be deleted
    remaining = sync_db.query(AnalysisJob).filter(
        AnalysisJob.id.in_([job1.id, job2.id])
    ).all()
    assert len(remaining) == 0
