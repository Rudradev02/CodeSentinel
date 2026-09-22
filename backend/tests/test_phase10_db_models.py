"""Tests for Phase 10 SQLAlchemy ORM models and relational schema."""

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.models.component import ComponentEdgeSnapshot, ComponentSnapshot
from backend.app.models.finding import FindingSnapshot
from backend.app.models.health import HealthDeductionSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot


@pytest.mark.asyncio
async def test_repository_model_crud(db_session: AsyncSession):
    """Verify Repository creation, attributes, and query."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="test-repo",
        path="/tmp/test-repo",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(repo)
    await db_session.commit()

    query = select(Repository).where(Repository.id == repo.id)
    result = await db_session.execute(query)
    fetched = result.scalar_one()

    assert fetched.id == repo.id
    assert fetched.name == "test-repo"
    assert fetched.path == "/tmp/test-repo"
    assert fetched.created_at is not None
    assert fetched.updated_at is not None


@pytest.mark.asyncio
async def test_repository_path_unique_constraint(db_session: AsyncSession):
    """Verify that registering duplicate repository paths fails unique constraint."""
    repo1 = Repository(
        id=str(uuid.uuid4()),
        name="repo-1",
        path="/tmp/duplicate-path",
    )
    db_session.add(repo1)
    await db_session.commit()

    repo2 = Repository(
        id=str(uuid.uuid4()),
        name="repo-2",
        path="/tmp/duplicate-path",
    )
    db_session.add(repo2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_analysis_snapshot_and_cascade_delete(db_session: AsyncSession):
    """Verify AnalysisSnapshot and cascade deletion of findings and components."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="cascade-test",
        path="/tmp/cascade-test",
    )
    db_session.add(repo)
    await db_session.commit()

    snapshot_id = str(uuid.uuid4())
    snapshot = AnalysisSnapshot(
        id=snapshot_id,
        repository_id=repo.id,
        created_at=datetime.now(timezone.utc),
        commit_hash="abc1234",
        branch="main",
        is_dirty=False,
        analyzer_version="0.1.0",
        status="COMPLETED",
        overall_score=95.0,
        overall_grade="A",
        architecture_score=90.0,
        architecture_grade="A",
        security_score=100.0,
        security_grade="A",
    )
    db_session.add(snapshot)

    finding = FindingSnapshot(
        id=str(uuid.uuid4()),
        snapshot_id=snapshot_id,
        finding_uuid=str(uuid.uuid4()),
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secret",
        category="SECURITY",
        severity="HIGH",
        confidence="HIGH",
        message="Secret found",
        description="A secret was hardcoded",
        remediation="Use environment variable",
        file_path="app/config.py",
        line_start=10,
        snippet='token = "[REDACTED_SECRET]"',
        language="python",
        evidence={"token_type": "api_key"},
    )
    db_session.add(finding)

    deduction = HealthDeductionSnapshot(
        id=str(uuid.uuid4()),
        snapshot_id=snapshot_id,
        category="SECURITY",
        rule_id="SEC-PY-001",
        points_deducted=15.0,
        reason="Hardcoded secret penalty",
    )
    db_session.add(deduction)

    component = ComponentSnapshot(
        id=str(uuid.uuid4()),
        snapshot_id=snapshot_id,
        component_id="backend.app",
        name="app",
        path="backend/app",
        layer="APPLICATION",
        afferent_coupling=1,
        efferent_coupling=2,
        instability=0.67,
        total_loc=150,
        file_count=3,
        files=["backend/app/main.py"],
    )
    db_session.add(component)

    edge = ComponentEdgeSnapshot(
        id=str(uuid.uuid4()),
        snapshot_id=snapshot_id,
        edge_id="backend.app->backend.db",
        source_component_id="backend.app",
        target_component_id="backend.db",
        weight=2,
        is_circular=False,
    )
    db_session.add(edge)
    await db_session.commit()

    # Query snapshot with relationships
    query = (
        select(AnalysisSnapshot)
        .where(AnalysisSnapshot.id == snapshot_id)
        .options(
            selectinload(AnalysisSnapshot.findings),
            selectinload(AnalysisSnapshot.deductions),
            selectinload(AnalysisSnapshot.components),
            selectinload(AnalysisSnapshot.component_edges),
        )
    )
    res = await db_session.execute(query)
    snap = res.scalar_one()

    assert len(snap.findings) == 1
    assert snap.findings[0].rule_id == "SEC-PY-001"
    assert len(snap.deductions) == 1
    assert snap.deductions[0].points_deducted == 15.0
    assert len(snap.components) == 1
    assert snap.components[0].component_id == "backend.app"
    assert len(snap.component_edges) == 1
    assert snap.component_edges[0].edge_id == "backend.app->backend.db"

    # Delete repository -> should cascade to snapshot and all child records
    await db_session.delete(repo)
    await db_session.commit()

    # Verify all records removed
    snap_check = await db_session.execute(select(AnalysisSnapshot).where(AnalysisSnapshot.id == snapshot_id))
    assert snap_check.scalar_one_or_none() is None

    finding_check = await db_session.execute(select(FindingSnapshot).where(FindingSnapshot.snapshot_id == snapshot_id))
    assert finding_check.scalar_one_or_none() is None

    comp_check = await db_session.execute(select(ComponentSnapshot).where(ComponentSnapshot.snapshot_id == snapshot_id))
    assert comp_check.scalar_one_or_none() is None
