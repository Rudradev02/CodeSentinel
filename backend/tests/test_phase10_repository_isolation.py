"""Tests for Phase 10 repository boundary isolation and multi-repo safety."""

from pathlib import Path
import uuid
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from backend.app.models.repository import Repository
from backend.app.services.persistence import PersistenceService

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project"


def test_repository_analysis_isolation(test_ctx):
    """Verify that Repository A cannot access Repository B's analyses, and history is strictly isolated."""
    async def _test():
        async with test_ctx.session_factory() as db_session:
            # 1. Create two repositories
            repo_a = Repository(
                id=str(uuid.uuid4()),
                name="repo-a",
                path=str((FIXTURE_PATH / "backend").resolve()),
            )
            repo_b = Repository(
                id=str(uuid.uuid4()),
                name="repo-b",
                path=str((FIXTURE_PATH / "frontend").resolve()),
            )
            db_session.add_all([repo_a, repo_b])
            await db_session.commit()

            config = AnalysisConfig()
            pipeline = AnalysisPipeline(analysis_config=config)

            # 2. Run and persist analysis for Repo A
            res_a = pipeline.run(target_path=FIXTURE_PATH / "backend", analysis_config=config)
            snap_a = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo_a.id,
                result=res_a,
            )

            # 3. Run and persist analysis for Repo B
            res_b = pipeline.run(target_path=FIXTURE_PATH / "frontend", analysis_config=config)
            snap_b = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo_b.id,
                result=res_b,
            )

            # 4. Enforce Isolation: Repo A can fetch snap_a, but CANNOT fetch snap_b
            fetch_a_for_a = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo_a.id,
                analysis_id=snap_a.id,
            )
            assert fetch_a_for_a is not None
            assert fetch_a_for_a.id == snap_a.id

            fetch_b_for_a = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo_a.id,
                analysis_id=snap_b.id,
            )
            assert fetch_b_for_a is None, "Security violation: Repo A was able to access Repo B's analysis snapshot!"

            # 5. Enforce Isolation: Repo B can fetch snap_b, but CANNOT fetch snap_a
            fetch_b_for_b = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo_b.id,
                analysis_id=snap_b.id,
            )
            assert fetch_b_for_b is not None
            assert fetch_b_for_b.id == snap_b.id

            fetch_a_for_b = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo_b.id,
                analysis_id=snap_a.id,
            )
            assert fetch_a_for_b is None, "Security violation: Repo B was able to access Repo A's analysis snapshot!"

            # 6. Listing isolation
            list_a, total_a = await PersistenceService.list_analysis_snapshots(
                db=db_session,
                repository_id=repo_a.id,
            )
            assert total_a == 1
            assert list_a[0].id == snap_a.id

            list_b, total_b = await PersistenceService.list_analysis_snapshots(
                db=db_session,
                repository_id=repo_b.id,
            )
            assert total_b == 1
            assert list_b[0].id == snap_b.id

            # 7. Cascade deletion isolation: Deleting Repo A must not affect Repo B
            await db_session.delete(repo_a)
            await db_session.commit()

            still_b = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo_b.id,
                analysis_id=snap_b.id,
            )
            assert still_b is not None
            assert still_b.id == snap_b.id

    test_ctx.run(_test())
