"""Integration tests for Phase 12 AI Enrichment REST API endpoints."""

from unittest.mock import MagicMock, patch
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.models.ai_enrichment import AIEnrichmentRecord
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.tests.conftest import FIXTURE_PATH, AsyncTestContext


@pytest.fixture
def api_test_data(test_ctx: AsyncTestContext) -> tuple[str, str, str]:
    """Seed test data for API testing."""
    repo_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())

    async def _seed():
        async with test_ctx.session_factory() as session:
            repo = Repository(id=repo_id, name="api_repo", path=FIXTURE_PATH)
            session.add(repo)
            snap = AnalysisSnapshot(id=snap_id, repository_id=repo_id, status="COMPLETED")
            session.add(snap)
            finding = FindingSnapshot(
                id=finding_id,
                snapshot_id=snap_id,
                finding_uuid=str(uuid.uuid4()),
                rule_id="SEC-PY-001",
                rule_name="Hardcoded Secret Key",
                category="SECURITY",
                severity="CRITICAL",
                confidence="HIGH",
                message="Secret key found",
                description="Hardcoded key in source",
                remediation="Use environment variable",
                file_path="backend/core/config.py",
                line_start=10,
                snippet="SECRET_KEY = 'secret'",
                language="python",
            )
            session.add(finding)
            await session.commit()

    test_ctx.run(_seed())
    return repo_id, snap_id, finding_id


def test_enqueue_finding_enrichment_returns_202(client_with_db: TestClient, api_test_data: tuple[str, str, str]):
    """Verify POST /enrich dispatches background worker task and returns 202 Accepted."""
    repo_id, snap_id, finding_id = api_test_data

    mock_task = MagicMock()
    mock_task.id = "mock-ai-task-777"

    with patch("backend.app.api.v1.endpoints.enrichment.run_ai_enrichment_task.delay", return_value=mock_task):
        res = client_with_db.post(
            f"/api/v1/repositories/{repo_id}/analyses/{snap_id}/findings/{finding_id}/enrich",
            json={"provider": "openrouter", "force_refresh": False},
        )

        assert res.status_code == 202
        data = res.json()
        assert data["finding_id"] == finding_id
        assert data["status"] == "QUEUED"
        assert "enrichment_id" in data


def test_get_finding_enrichment_success_and_404(
    client_with_db: TestClient,
    test_ctx: AsyncTestContext,
    api_test_data: tuple[str, str, str],
):
    """Verify GET /enrichment returns 404 when absent, and 200 with DTO when present."""
    repo_id, snap_id, finding_id = api_test_data

    # 1. Initially absent -> 404
    res_404 = client_with_db.get(
        f"/api/v1/repositories/{repo_id}/analyses/{snap_id}/findings/{finding_id}/enrichment"
    )
    assert res_404.status_code == 404

    # 2. Seed enrichment record
    async def _add_enrichment():
        async with test_ctx.session_factory() as session:
            record = AIEnrichmentRecord(
                id=str(uuid.uuid4()),
                finding_id=finding_id,
                snapshot_id=snap_id,
                repository_id=repo_id,
                status="COMPLETED",
                provider="openrouter",
                model="anthropic/claude-3.5-sonnet",
                is_likely_true_positive=True,
                confidence_score=0.91,
                risk_summary="Valid critical credential exposure.",
                technical_reasoning="Hardcoded key allows unauthorized token minting.",
                prescribed_remediation="Read from os.environ.",
                proposed_patch={
                    "file_path": "backend/core/config.py",
                    "original_snippet": "SECRET_KEY = 'secret'",
                    "patched_snippet": "SECRET_KEY = os.environ['SECRET_KEY']",
                    "unified_diff": "--- a/backend/core/config.py\n+++ b/backend/core/config.py\n@@ -10,1 +10,1 @@\n-SECRET_KEY = 'secret'\n+SECRET_KEY = os.environ['SECRET_KEY']\n",
                    "explanation": "Loads key from environment",
                },
            )
            session.add(record)
            await session.commit()

    test_ctx.run(_add_enrichment())

    # 3. Retrieve enrichment -> 200 OK
    res_200 = client_with_db.get(
        f"/api/v1/repositories/{repo_id}/analyses/{snap_id}/findings/{finding_id}/enrichment"
    )
    assert res_200.status_code == 200
    data = res_200.json()
    assert data["finding_id"] == finding_id
    assert data["status"] == "COMPLETED"
    assert data["is_likely_true_positive"] is True
    assert data["confidence_score"] == 0.91
    assert data["proposed_patch"] is not None
    assert data["proposed_patch"]["patched_snippet"] == "SECRET_KEY = os.environ['SECRET_KEY']"


def test_api_repository_isolation_on_enrichment(client_with_db: TestClient, api_test_data: tuple[str, str, str]):
    """Verify cross-repository lookups for finding enrichment return 404."""
    _, snap_id, finding_id = api_test_data
    other_repo_id = str(uuid.uuid4())

    res = client_with_db.get(
        f"/api/v1/repositories/{other_repo_id}/analyses/{snap_id}/findings/{finding_id}/enrichment"
    )
    assert res.status_code == 404
