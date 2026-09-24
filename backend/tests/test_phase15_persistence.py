"""Tests for Phase 15 Call Graph persistence, interprocedural evidence, and API endpoint."""

import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from analyzer.models.findings import Finding, FindingCategory, FindingSeverity, FindingConfidence, SourceLocation, EvidenceType
from analyzer.models.results import AnalysisResult, AnalysisStatus, RepositoryInfo
from backend.app.models.repository import Repository
from backend.app.schemas.callgraph import CallGraphSummaryDTO
from backend.app.services.persistence import PersistenceService


FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project"


def test_callgraph_summary_persistence_and_reconstruction(test_ctx):
    """Verify call_graph_summary and INTER_PROCEDURAL_TAINT evidence persist and reconstruct."""
    async def _test():
        async with test_ctx.session_factory() as db_session:
            repo = Repository(
                id=str(uuid.uuid4()),
                name="test_callgraph_repo",
                path=str(FIXTURE_PATH.resolve()),
            )
            db_session.add(repo)
            await db_session.commit()

            cg_summary = {
                "total_functions": 15,
                "total_call_edges": 25,
                "resolved_local": 18,
                "resolved_import": 5,
                "unresolved": 2,
                "resolution_rate": 0.92,
                "summarized_functions": 14,
                "unsummarized_functions": 1,
                "interprocedural_findings_count": 1,
                "max_call_depth_reached": 3,
            }

            finding = Finding(
                id=str(uuid.uuid4()),
                rule_id="SEC-PY-011",
                rule_name="Interprocedural SQL Injection",
                category=FindingCategory.SECURITY,
                evidence_type=EvidenceType.DETERMINISTIC,
                severity=FindingSeverity.CRITICAL,
                confidence=FindingConfidence.HIGH,
                message="Tainted SQL query executed across function call",
                description="Cross-function taint trace",
                remediation="Use parameterized queries",
                location=SourceLocation(file_path="views.py", line_start=14, line_end=14),
                code_snippet="cursor.execute(query)",
                evidence={
                    "flow_type": "INTER_PROCEDURAL_TAINT",
                    "total_depth": 2,
                    "files_involved": ["utils/query.py", "views.py"],
                    "path_summary": "build_query -> handle_request",
                },
            )

            result = AnalysisResult(
                id=str(uuid.uuid4()),
                status=AnalysisStatus.COMPLETED,
                repository=RepositoryInfo(name="test_callgraph_repo", local_path=str(FIXTURE_PATH.resolve())),
                security_findings=[finding],
                architecture_findings=[],
                call_graph_summary=cg_summary,
            )

            snapshot = await PersistenceService.save_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                result=result,
            )

            assert snapshot.call_graph_summary == cg_summary

            retrieved = await PersistenceService.get_analysis_snapshot(
                db=db_session,
                repository_id=repo.id,
                analysis_id=snapshot.id,
            )
            assert retrieved is not None
            assert retrieved.call_graph_summary == cg_summary

            dto = PersistenceService.reconstruct_analysis_dto(
                snapshot=retrieved,
                repo_path=FIXTURE_PATH,
                repo_name=repo.name,
            )

            assert dto.call_graph_summary == cg_summary
            assert len(dto.findings) == 1
            assert dto.findings[0].dataflow_evidence is not None
            assert dto.findings[0].dataflow_evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT"
            assert dto.findings[0].dataflow_evidence.get("total_depth") == 2

    import asyncio
    asyncio.run(_test())


def test_callgraph_api_endpoint(client_with_db: TestClient):
    """Verify GET /api/v1/repositories/{repo_id}/analyses/{analysis_id}/callgraph endpoint."""
    path_a = FIXTURE_PATH / "backend"
    path_b = FIXTURE_PATH / "frontend"

    reg_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": str(path_a.resolve()), "name": "CG API Test Repo"},
    )
    assert reg_res.status_code == 201
    repo_id = reg_res.json()["id"]

    cg_summary = {
        "total_functions": 10,
        "total_call_edges": 12,
        "resolved_local": 8,
        "resolved_import": 3,
        "unresolved": 1,
        "resolution_rate": 0.916,
        "summarized_functions": 10,
        "unsummarized_functions": 0,
        "interprocedural_findings_count": 1,
        "max_call_depth_reached": 2,
    }

    sync_payload = {
        "id": str(uuid.uuid4()),
        "status": "COMPLETED",
        "repository": {
            "name": "CG API Test Repo",
            "local_path": str(path_a.resolve()),
        },
        "security_findings": [],
        "architecture_findings": [],
        "call_graph_summary": cg_summary,
    }
    sync_res = client_with_db.post(
        f"/api/v1/repositories/{repo_id}/snapshots",
        json=sync_payload,
    )
    assert sync_res.status_code == 201
    analysis_id = sync_payload["id"]

    # 1. Success case: retrieve call graph summary
    cg_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses/{analysis_id}/callgraph")
    assert cg_res.status_code == 200
    dto = CallGraphSummaryDTO.model_validate(cg_res.json())
    assert dto.analysis_id == analysis_id
    assert dto.total_functions == 10
    assert dto.total_call_edges == 12
    assert dto.resolution_rate == 0.916

    # 2. 404 for unknown repository
    bad_repo_res = client_with_db.get(f"/api/v1/repositories/nonexistent-repo/analyses/{analysis_id}/callgraph")
    assert bad_repo_res.status_code == 404

    # 3. 404 for unknown analysis
    bad_analysis_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses/nonexistent-analysis/callgraph")
    assert bad_analysis_res.status_code == 404

    # 4. 404 for cross-repository isolation check
    reg2_res = client_with_db.post(
        "/api/v1/repositories",
        json={"path": str(path_b.resolve()), "name": "CG API Second Repo"},
    )
    assert reg2_res.status_code == 201
    repo2_id = reg2_res.json()["id"]

    cross_res = client_with_db.get(f"/api/v1/repositories/{repo2_id}/analyses/{analysis_id}/callgraph")
    assert cross_res.status_code == 404

    # 5. 404 when analysis has no call graph data
    no_cg_payload = {
        "id": str(uuid.uuid4()),
        "status": "COMPLETED",
        "repository": {
            "name": "CG API Test Repo",
            "local_path": str(path_a.resolve()),
        },
        "security_findings": [],
        "architecture_findings": [],
        "call_graph_summary": None,
    }
    sync_no_cg = client_with_db.post(
        f"/api/v1/repositories/{repo_id}/snapshots",
        json=no_cg_payload,
    )
    assert sync_no_cg.status_code == 201
    no_cg_res = client_with_db.get(f"/api/v1/repositories/{repo_id}/analyses/{no_cg_payload['id']}/callgraph")
    assert no_cg_res.status_code == 404
    assert "no call graph data" in no_cg_res.json()["detail"].lower()
