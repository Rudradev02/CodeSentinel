"""Tests for Phase 10 analysis snapshot immutability and append-only history."""

from pathlib import Path
import uuid
import pytest
from sqlalchemy import select

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.services.persistence import PersistenceService

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project"


def test_snapshot_immutability_across_multiple_runs(test_ctx):
    """Verify that multiple analysis runs create independent immutable snapshots without mutating earlier ones."""
    async def _test():
        async with test_ctx.session_factory() as db_session:
            repo = Repository(
                id=str(uuid.uuid4()),
                name="immutability-test-repo",
                path=str(FIXTURE_PATH.resolve()),
            )
            db_session.add(repo)
            await db_session.commit()

            config = AnalysisConfig()
            pipeline = AnalysisPipeline(analysis_config=config)

            # Run Analysis 1
            result_1 = pipeline.run(target_path=FIXTURE_PATH, analysis_config=config)
            snapshot_1 = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                result=result_1,
            )
            snap_1_id = snapshot_1.id
            snap_1_score = snapshot_1.overall_score
            snap_1_findings_count = snapshot_1.total_findings

            # Run Analysis 2 (simulating a subsequent run)
            result_2 = pipeline.run(target_path=FIXTURE_PATH, analysis_config=config)
            snapshot_2 = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                result=result_2,
            )
            snap_2_id = snapshot_2.id

            # IDs must be distinct
            assert snap_1_id != snap_2_id

            # Fetch snapshot 1 again and verify it is completely unchanged
            retrieved_1 = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                analysis_id=snap_1_id,
            )
            assert retrieved_1 is not None
            assert retrieved_1.id == snap_1_id
            assert retrieved_1.overall_score == snap_1_score
            assert retrieved_1.total_findings == snap_1_findings_count

            # Fetch snapshot 2 and verify it is intact
            retrieved_2 = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                analysis_id=snap_2_id,
            )
            assert retrieved_2 is not None
            assert retrieved_2.id == snap_2_id

            # Verify history list contains both snapshots
            snapshots, total = await PersistenceService.list_analysis_snapshots(
                db=db_session,
                repository_id=repo.id,
            )
            assert total == 2
            snapshot_ids = [s.id for s in snapshots]
            assert snap_1_id in snapshot_ids
            assert snap_2_id in snapshot_ids

    test_ctx.run(_test())


def test_repository_update_does_not_mutate_snapshot(test_ctx):
    """Verify that renaming or updating a repository does not alter historical analysis snapshots."""
    async def _test():
        async with test_ctx.session_factory() as db_session:
            repo = Repository(
                id=str(uuid.uuid4()),
                name="initial-name",
                path=str(FIXTURE_PATH.resolve()),
            )
            db_session.add(repo)
            await db_session.commit()

            config = AnalysisConfig()
            pipeline = AnalysisPipeline(analysis_config=config)
            result = pipeline.run(target_path=FIXTURE_PATH, analysis_config=config)

            snapshot = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                result=result,
            )
            original_snapshot_created_at = snapshot.created_at

            # Mutate repository
            repo.name = "renamed-repo"
            await db_session.commit()

            # Re-fetch snapshot and verify it was not modified
            fresh_snapshot = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                analysis_id=snapshot.id,
            )
            assert fresh_snapshot is not None
            assert fresh_snapshot.id == snapshot.id
            assert fresh_snapshot.created_at == original_snapshot_created_at
            assert fresh_snapshot.overall_score == snapshot.overall_score

    test_ctx.run(_test())
