"""Unit and integration tests for Phase 28 distributed worker fleet orchestration."""

from pathlib import Path
import tempfile
import uuid
import pytest
from unittest.mock import MagicMock, patch

from backend.app.models.organization import Organization
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.workspace import Workspace, WorkspaceRepository, WorkspaceSnapshot
from backend.app.workers import celery_config
from backend.app.workers.tasks import run_workspace_scan_task


def test_celery_multiqueue_configuration():
    """Verify Celery config includes Phase 28 multi-queue routing."""
    queue_names = [q.name for q in celery_config.task_queues]
    assert "analysis" in queue_names
    assert "workspace_dag" in queue_names
    assert "repo_heavy" in queue_names
    assert "repo_fast" in queue_names
    assert "compliance_attestation" in queue_names

    routes = celery_config.task_routes
    assert routes["backend.app.workers.tasks.run_analysis_task"]["queue"] == "analysis"
    assert routes["backend.app.workers.tasks.run_workspace_scan_task"]["queue"] == "workspace_dag"


def test_run_workspace_scan_not_found(sync_db):
    """Verify task returns NOT_FOUND when workspace ID does not exist."""
    fake_id = str(uuid.uuid4())

    with patch("backend.app.workers.tasks.get_sync_db") as mock_db_ctx:
        mock_db_ctx.return_value.__enter__.return_value = sync_db
        res = run_workspace_scan_task.apply(args=[fake_id], task_id="test-task-123").result

    assert res["status"] == "NOT_FOUND"


def test_run_workspace_scan_end_to_end(sync_db, tmp_path):
    """Verify end-to-end execution of run_workspace_scan_task across DAG waves."""
    # 1. Setup Organization & Workspace
    org = Organization(name="Fintech Org", slug=f"fintech-{uuid.uuid4().hex[:6]}")
    sync_db.add(org)
    sync_db.flush()

    repo1_dir = tmp_path / "repo_core"
    repo1_dir.mkdir()
    (repo1_dir / "core.py").write_text("def sanitize(x): return x.strip()", encoding="utf-8")

    repo2_dir = tmp_path / "repo_api"
    repo2_dir.mkdir()
    (repo2_dir / "api.py").write_text("def handle(req): pass", encoding="utf-8")

    repo1 = Repository(name="core-lib", path=str(repo1_dir))
    repo2 = Repository(name="api-gateway", path=str(repo2_dir))
    sync_db.add_all([repo1, repo2])
    sync_db.flush()

    ws = Workspace(
        organization_id=org.id,
        name="Platform Workspace",
        slug=f"platform-{uuid.uuid4().hex[:6]}",
        manifest_path=str(tmp_path / "dummy-manifest.yaml"),
    )
    sync_db.add(ws)
    sync_db.flush()

    # Link repos: api-gateway depends on core-lib
    link1 = WorkspaceRepository(
        workspace_id=ws.id,
        repository_id=repo1.id,
        role="INTERNAL_LIBRARY",
        criticality="HIGH",
        depends_on=[],
    )
    link2 = WorkspaceRepository(
        workspace_id=ws.id,
        repository_id=repo2.id,
        role="PUBLIC_ENTRYPOINT",
        criticality="CRITICAL",
        depends_on=[repo1.id],
    )
    sync_db.add_all([link1, link2])
    sync_db.commit()

    with patch("backend.app.workers.tasks.get_sync_db") as mock_db_ctx:
        mock_db_ctx.return_value.__enter__.return_value = sync_db
        result = run_workspace_scan_task.apply(args=[ws.id], task_id="test-task-456").result

    assert result["status"] == "COMPLETED"
    assert "snapshot_id" in result

    # Verify WorkspaceSnapshot persisted in DB
    ws_snap = sync_db.query(WorkspaceSnapshot).filter_by(id=result["snapshot_id"]).first()
    assert ws_snap is not None
    assert ws_snap.workspace_id == ws.id
    assert len(ws_snap.repository_snapshot_ids) == 2
    assert ws_snap.composite_health_score > 0
    assert ws_snap.composite_grade in ("A", "B", "C", "D", "F")
    assert ws_snap.merkle_workspace_root != ""
    assert ws_snap.attestation_envelope is not None
    assert ws_snap.compliance_suite is not None

    # Verify constituent AnalysisSnapshots are linked
    for snap_id in ws_snap.repository_snapshot_ids:
        snap = sync_db.query(AnalysisSnapshot).filter_by(id=snap_id).first()
        assert snap is not None
        assert snap.workspace_snapshot_id == ws_snap.id
