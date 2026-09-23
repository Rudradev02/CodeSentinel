"""Tests for Phase 14 TrendService: quality trajectories, defect velocity, and drift."""

from datetime import datetime, timedelta, timezone
import pytest
import uuid

from backend.app.models.component import ComponentSnapshot
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.services.trend_service import TrendService
from backend.tests.conftest import AsyncTestContext


@pytest.mark.asyncio
async def test_trend_service_empty_repository(test_ctx: AsyncTestContext):
    """Empty repository returns 0 snapshots and clean default trend DTO."""
    async with test_ctx.session_factory() as session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Empty Repo",
            path="C:/test/empty",
        )
        session.add(repo)
        await session.commit()

        trend = await TrendService.get_repository_trends(
            db=session,
            repository_id=repo.id,
        )

        assert trend.repository_id == repo.id
        assert trend.total_snapshots == 0
        assert len(trend.health_trajectory) == 0
        assert len(trend.defect_velocity) == 0
        assert trend.overall_health_delta == 0.0
        assert trend.defect_burndown_rate == 0.0


@pytest.mark.asyncio
async def test_trend_service_nonexistent_repository(test_ctx: AsyncTestContext):
    """Nonexistent repository raises ValueError."""
    async with test_ctx.session_factory() as session:
        with pytest.raises(ValueError) as exc:
            await TrendService.get_repository_trends(
                db=session,
                repository_id="nonexistent-repo-id",
            )
        assert "not found" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_trend_service_trajectory_and_defect_velocity(test_ctx: AsyncTestContext):
    """Verify health trajectory, defect velocity transitions, and component drift."""
    async with test_ctx.session_factory() as session:
        repo = Repository(
            id=str(uuid.uuid4()),
            name="Trend Test Repo",
            path="C:/test/repo",
        )
        session.add(repo)

        now = datetime.now(timezone.utc)

        # Snapshot 1: Baseline run with 2 findings
        snap1 = AnalysisSnapshot(
            id="snap-1",
            repository_id=repo.id,
            created_at=now - timedelta(days=2),
            overall_score=75.0,
            overall_grade="C",
            architecture_score=70.0,
            security_score=80.0,
            total_findings=2,
            critical_count=1,
            high_count=1,
            branch="main",
        )
        f1 = FindingSnapshot(
            snapshot_id="snap-1",
            finding_uuid="find-uuid-1",
            rule_id="SEC-PY-001",
            rule_name="Hardcoded Secret",
            category="SECURITY",
            severity="CRITICAL",
            confidence="HIGH",
            message="Secret found",
            description="desc",
            remediation="fix",
            file_path="app/config.py",
            line_start=12,
            snippet="API_KEY = 'secret'",
        )
        f2 = FindingSnapshot(
            snapshot_id="snap-1",
            finding_uuid="find-uuid-2",
            rule_id="ARC-001",
            rule_name="Circular Dependency",
            category="ARCHITECTURE",
            severity="HIGH",
            confidence="HIGH",
            message="Cycle detected",
            description="desc",
            remediation="fix",
            file_path="app/models.py",
            line_start=5,
            snippet="import views",
        )
        c1_snap1 = ComponentSnapshot(
            snapshot_id="snap-1",
            component_id="app.core",
            name="Core",
            path="app/core",
            instability=0.8,
            betweenness_centrality=0.45,
        )

        session.add_all([snap1, f1, f2, c1_snap1])

        # Snapshot 2: Follow-up run: resolved f1, kept f2, added f3
        snap2 = AnalysisSnapshot(
            id="snap-2",
            repository_id=repo.id,
            created_at=now,
            overall_score=85.0,
            overall_grade="B",
            architecture_score=80.0,
            security_score=90.0,
            total_findings=2,
            critical_count=0,
            high_count=2,
            branch="main",
        )
        f2_snap2 = FindingSnapshot(
            snapshot_id="snap-2",
            finding_uuid="find-uuid-2",
            rule_id="ARC-001",
            rule_name="Circular Dependency",
            category="ARCHITECTURE",
            severity="HIGH",
            confidence="HIGH",
            message="Cycle detected",
            description="desc",
            remediation="fix",
            file_path="app/models.py",
            line_start=5,
            snippet="import views",
        )
        f3_snap2 = FindingSnapshot(
            snapshot_id="snap-2",
            finding_uuid="find-uuid-3",
            rule_id="ARC-003",
            rule_name="God Module",
            category="ARCHITECTURE",
            severity="HIGH",
            confidence="HIGH",
            message="God module detected",
            description="desc",
            remediation="fix",
            file_path="app/service.py",
            line_start=1,
            snippet="class GodService: ...",
        )
        c1_snap2 = ComponentSnapshot(
            snapshot_id="snap-2",
            component_id="app.core",
            name="Core",
            path="app/core",
            instability=0.6,
            betweenness_centrality=0.30,
        )

        session.add_all([snap2, f2_snap2, f3_snap2, c1_snap2])
        await session.commit()

        # Compute trends
        trend = await TrendService.get_repository_trends(
            db=session,
            repository_id=repo.id,
        )

        assert trend.total_snapshots == 2
        assert len(trend.health_trajectory) == 2
        assert trend.health_trajectory[0].overall_score == 75.0
        assert trend.health_trajectory[1].overall_score == 85.0
        assert trend.overall_health_delta == 10.0  # 85 - 75

        # Defect Velocity
        assert len(trend.defect_velocity) == 2
        # Snapshot 1: baseline
        v1 = trend.defect_velocity[0]
        assert v1.new_defects == 2
        assert v1.resolved_defects == 0
        assert v1.net_change == 2

        # Snapshot 2: resolved f1 (-1), introduced f3 (+1), kept f2 (unchanged)
        v2 = trend.defect_velocity[1]
        assert v2.new_defects == 1
        assert v2.resolved_defects == 1
        assert v2.net_change == 0

        # Component drift: instability dropped from 0.8 to 0.6 => drift -0.2
        assert len(trend.component_drift) == 1
        cd = trend.component_drift[0]
        assert cd.component_id == "app.core"
        assert cd.baseline_instability == 0.8
        assert cd.current_instability == 0.6
        assert cd.instability_drift == -0.2
        assert cd.current_centrality == 0.30
