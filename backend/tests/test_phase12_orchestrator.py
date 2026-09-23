"""Integration tests for AIEnrichmentOrchestrator and relational caching."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.app.models.ai_enrichment import AIEnrichmentRecord
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.services.ai.orchestrator import AIEnrichmentOrchestrator
from backend.app.services.ai.providers.base import LLMResponse
from backend.tests.conftest import FIXTURE_PATH, AsyncTestContext


@pytest.fixture
def populated_db(sync_db: Session) -> tuple[str, str, str]:
    """Create Repository, Snapshot, and Finding in sync test DB."""
    repo = Repository(
        id=str(uuid.uuid4()),
        name="sample_repo",
        path=FIXTURE_PATH,
    )
    sync_db.add(repo)
    sync_db.commit()

    snapshot = AnalysisSnapshot(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        status="COMPLETED",
        total_files=5,
        total_loc=200,
    )
    sync_db.add(snapshot)
    sync_db.commit()

    finding = FindingSnapshot(
        id=str(uuid.uuid4()),
        snapshot_id=snapshot.id,
        finding_uuid=str(uuid.uuid4()),
        rule_id="SEC-PY-005",
        rule_name="Raw SQL Query String Formatting",
        category="SECURITY",
        severity="HIGH",
        confidence="HIGH",
        message="SQL Injection candidate",
        description="Raw string formatting in SQL query",
        remediation="Use parameterized queries",
        file_path="backend/models/user.py",
        line_start=14,
        snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
        language="python",
    )
    sync_db.add(finding)
    sync_db.commit()

    return repo.id, snapshot.id, finding.id


def test_orchestrator_enrich_finding_sync_success(sync_db: Session, populated_db: tuple[str, str, str]):
    """Verify orchestrator runs complete triage cycle and records AIEnrichmentRecord."""
    repo_id, snap_id, finding_id = populated_db

    mock_llm_json = {
        "finding_id": finding_id,
        "is_likely_true_positive": True,
        "confidence_score": 0.94,
        "risk_summary": "High risk of SQL injection through unvalidated parameter.",
        "technical_reasoning": "Formatting string directly without bind parameters.",
        "assumptions_and_limitations": ["Assumes user_id is untrusted input"],
        "prescribed_remediation": "Use :user_id parameter binding.",
        "proposed_patch": {
            "file_path": "backend/models/user.py",
            "original_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
            "patched_snippet": "query = 'SELECT * FROM users WHERE id = :user_id'",
            "unified_diff": "--- a/backend/models/user.py\n+++ b/backend/models/user.py\n@@ -14,1 +14,1 @@\n-query = f'SELECT * FROM users WHERE id = {user_id}'\n+query = 'SELECT * FROM users WHERE id = :user_id'\n",
            "explanation": "Replaces f-string with bind parameter",
        },
    }

    mock_response = LLMResponse(
        raw_content=json.dumps(mock_llm_json),
        parsed_json=mock_llm_json,
        model_name="anthropic/claude-3.5-sonnet",
        provider_name="openrouter",
    )

    with patch("backend.app.services.ai.orchestrator.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.AI_ENABLED = True
        mock_get_settings.return_value = mock_settings
        with patch.object(AIEnrichmentOrchestrator, "get_provider") as mock_get_prov:
            mock_provider = MagicMock()
            mock_provider.generate_sync.return_value = mock_response
            mock_get_prov.return_value = (mock_provider, "openrouter", "anthropic/claude-3.5-sonnet")


            record = AIEnrichmentOrchestrator.enrich_finding_sync(
                db=sync_db,
                finding_id=finding_id,
            )

            assert record.status == "COMPLETED"
            assert record.is_likely_true_positive is True
            assert record.confidence_score == 0.94
            assert record.proposed_patch is not None
            assert record.proposed_patch["patched_snippet"] == "query = 'SELECT * FROM users WHERE id = :user_id'"

            # Verify finding updated
            f = sync_db.query(FindingSnapshot).filter_by(id=finding_id).first()
            assert f.ai_validation_status == "TRUE_POSITIVE"


def test_orchestrator_cache_hit_avoids_llm_call(sync_db: Session, populated_db: tuple[str, str, str]):
    """Verify duplicate enrichment request returns cached record without querying LLM."""
    repo_id, snap_id, finding_id = populated_db

    # Pre-seed a completed enrichment record
    record = AIEnrichmentRecord(
        finding_id=finding_id,
        snapshot_id=snap_id,
        repository_id=repo_id,
        status="COMPLETED",
        provider="openrouter",
        model="anthropic/claude-3.5-sonnet",
        prompt_version="v1",
        is_likely_true_positive=False,
        confidence_score=0.89,
        risk_summary="Cached assessment",
    )
    sync_db.add(record)
    sync_db.commit()

    with patch.object(AIEnrichmentOrchestrator, "get_provider") as mock_get_prov:
        mock_provider = MagicMock()
        mock_get_prov.return_value = (mock_provider, "openrouter", "anthropic/claude-3.5-sonnet")

        cached = AIEnrichmentOrchestrator.enrich_finding_sync(
            db=sync_db,
            finding_id=finding_id,
            force_refresh=False,
        )

        assert cached.id == record.id
        assert cached.risk_summary == "Cached assessment"
        # LLM generate_sync must NOT have been called
        mock_provider.generate_sync.assert_not_called()
