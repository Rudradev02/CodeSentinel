"""Persistence service for saving and reconstructing immutable analysis snapshots."""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Optional
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload

from analyzer.models.results import AnalysisResult
from backend.app.api.v1.endpoints.analyze import infer_language
from backend.app.models.component import ComponentEdgeSnapshot, ComponentSnapshot
from backend.app.models.finding import FindingSnapshot
from backend.app.models.health import HealthDeductionSnapshot
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.schemas.analysis import (
    AnalysisResultDTO,
    AnalysisSummaryDTO,
    ComponentCouplingDTO,
    ComponentEdgeDTO,
    ComponentGraphDTO,
    ComponentNodeDTO,
    DeductionDTO,
    DiagnosticDTO,
    EvidenceDTO,
    FindingDTO,
    HealthScoreDTO,
    LocationDTO,
    SubScoreDTO,
)

# Regex pattern to redact obvious secrets in persisted finding snippets
_SECRET_PATTERN = re.compile(
    r'(?i)(password|secret|token|api[_-]?key|private[_-]?key|bearer)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?'
)


def _sanitize_snippet(rule_id: str, snippet: str) -> str:
    """Redact raw secrets from snippet before persistence if finding relates to secrets."""
    if not snippet:
        return ""
    # If the finding rule is specifically a secret or credential detection rule
    if "SEC-PY-001" in rule_id or "SEC-JS-004" in rule_id or "SECRET" in rule_id:
        return _SECRET_PATTERN.sub(r'\1: "[REDACTED_SECRET]"', snippet)
    return snippet


def _build_snapshot_entities(
    repository_id: str,
    result: AnalysisResult,
    config_dict: Optional[dict[str, Any]] = None,
) -> tuple[
    AnalysisSnapshot,
    list[FindingSnapshot],
    list[HealthDeductionSnapshot],
    list[ComponentSnapshot],
    list[ComponentEdgeSnapshot],
]:
    """Build all ORM entities for an AnalysisResult in-memory without database operations."""
    all_findings = result.security_findings + result.architecture_findings

    # 1. Compute summary counters
    total_findings = len(all_findings)
    critical_count = result.security_summary.critical
    high_count = result.security_summary.high + sum(
        1 for f in result.architecture_findings if getattr(f.severity, "value", str(f.severity)) == "HIGH"
    )
    medium_count = result.security_summary.medium + sum(
        1 for f in result.architecture_findings if getattr(f.severity, "value", str(f.severity)) == "MEDIUM"
    )
    low_count = result.security_summary.low + sum(
        1 for f in result.architecture_findings if getattr(f.severity, "value", str(f.severity)) == "LOW"
    )
    info_count = result.security_summary.info + sum(
        1 for f in result.architecture_findings if getattr(f.severity, "value", str(f.severity)) == "INFO"
    )

    circular_deps = result.architecture_summary.circular_dependencies_count
    circular_comps = (
        result.graph.component_graph.circular_components_count
        if result.graph and result.graph.component_graph
        else 0
    )

    # Health scoring defaults
    overall_score = result.health.overall_score if result.health else 100.0
    overall_grade = result.health.overall_grade if result.health else "A"
    arch_score = result.health.architecture_health.score if result.health else 100.0
    arch_grade = result.health.architecture_health.grade if result.health else "A"
    sec_score = result.health.security_posture.score if result.health else 100.0
    sec_grade = result.health.security_posture.grade if result.health else "A"
    total_deductions = result.health.total_deductions_count if result.health else 0
    health_summary = result.health.summary if result.health else None

    # Diagnostics payload
    diagnostics_payload = [
        {
            "file_path": d.file_path,
            "source_module": d.source_module,
            "line_number": d.line_number,
            "diagnostic_type": d.diagnostic_type,
            "message": d.message,
            "reason": d.reason,
            "assigned_category": d.assigned_category,
        }
        for d in result.dependency_diagnostics
    ]

    # 2. Build AnalysisSnapshot entity
    snapshot = AnalysisSnapshot(
        id=result.id,
        repository_id=repository_id,
        created_at=datetime.now(timezone.utc),
        commit_hash=result.repository.commit_hash,
        branch=result.repository.branch,
        is_dirty=result.repository.is_dirty,
        analyzer_version=result.metadata.engine_version or "0.1.0",
        status=result.status.value if hasattr(result.status, "value") else str(result.status),
        duration_seconds=result.metadata.duration_seconds or 0.0,
        total_files=result.repository.total_files,
        total_loc=result.repository.total_loc,
        configuration=config_dict,
        overall_score=overall_score,
        overall_grade=overall_grade,
        architecture_score=arch_score,
        architecture_grade=arch_grade,
        security_score=sec_score,
        security_grade=sec_grade,
        total_deductions_count=total_deductions,
        health_summary=health_summary,
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        circular_dependencies_count=circular_deps,
        circular_components_count=circular_comps,
        diagnostics_payload=diagnostics_payload,
        call_graph_summary=getattr(result, "call_graph_summary", None),
    )

    # 3. Add Finding snapshots
    finding_records: list[FindingSnapshot] = []
    for f in all_findings:
        lang = infer_language(f.location.file_path)
        clean_snippet = _sanitize_snippet(f.rule_id, f.code_snippet)

        finding_record = FindingSnapshot(
            id=str(uuid.uuid4()),
            snapshot_id=snapshot.id,
            finding_uuid=f.id,
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            category=f.category.value if hasattr(f.category, "value") else str(f.category),
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            message=f.message or f.rule_name,
            description=f.description,
            remediation=f.remediation,
            file_path=f.location.file_path,
            line_start=f.location.line_start,
            line_end=f.location.line_end,
            column_start=f.location.col_start,
            column_end=f.location.col_end,
            snippet=clean_snippet,
            language=lang,
            evidence=f.evidence,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            ai_validation_status=(
                getattr(f, "ai_validation_status", None).value
                if hasattr(getattr(f, "ai_validation_status", None), "value")
                else (str(getattr(f, "ai_validation_status", None)) if getattr(f, "ai_validation_status", None) else None)
            ),
        )
        finding_records.append(finding_record)

    # 4. Add Health Deduction snapshots
    deduction_records: list[HealthDeductionSnapshot] = []
    if result.health:
        for d in result.health.architecture_health.deductions:
            deduction_records.append(
                HealthDeductionSnapshot(
                    id=str(uuid.uuid4()),
                    snapshot_id=snapshot.id,
                    category=d.category,
                    rule_id=d.rule_id,
                    points_deducted=d.points_deducted,
                    reason=d.reason,
                    finding_id=d.finding_id,
                    item_count=d.item_count,
                )
            )
        for d in result.health.security_posture.deductions:
            deduction_records.append(
                HealthDeductionSnapshot(
                    id=str(uuid.uuid4()),
                    snapshot_id=snapshot.id,
                    category=d.category,
                    rule_id=d.rule_id,
                    points_deducted=d.points_deducted,
                    reason=d.reason,
                    finding_id=d.finding_id,
                    item_count=d.item_count,
                )
            )

    # 5. Add Component Graph snapshots
    component_records: list[ComponentSnapshot] = []
    edge_records: list[ComponentEdgeSnapshot] = []
    if result.graph and result.graph.component_graph:
        cg = result.graph.component_graph
        for n in cg.nodes:
            component_records.append(
                ComponentSnapshot(
                    id=str(uuid.uuid4()),
                    snapshot_id=snapshot.id,
                    component_id=n.id,
                    name=n.id.split(".")[-1] if "." in n.id else n.id,
                    path=n.path,
                    layer=n.layer,
                    afferent_coupling=n.metrics.afferent_coupling,
                    efferent_coupling=n.metrics.efferent_coupling,
                    instability=n.metrics.instability,
                    total_loc=n.metrics.total_loc,
                    file_count=n.metrics.file_count,
                    betweenness_centrality=getattr(n.metrics, "betweenness_centrality", 0.0),
                    in_degree_centrality=getattr(n.metrics, "in_degree_centrality", 0.0),
                    out_degree_centrality=getattr(n.metrics, "out_degree_centrality", 0.0),
                    files=n.files,
                )
            )
        for e in cg.edges:
            edge_records.append(
                ComponentEdgeSnapshot(
                    id=str(uuid.uuid4()),
                    snapshot_id=snapshot.id,
                    edge_id=e.id,
                    source_component_id=e.source,
                    target_component_id=e.target,
                    weight=e.weight,
                    is_circular=getattr(e, "is_circular", False),
                )
            )

    return snapshot, finding_records, deduction_records, component_records, edge_records


class PersistenceService:
    """Handles atomic storage and high-fidelity reconstruction of AnalysisSnapshots."""

    @staticmethod
    async def save_analysis_snapshot(
        db: AsyncSession,
        repository_id: str,
        result: AnalysisResult,
        config_dict: Optional[dict[str, Any]] = None,
    ) -> AnalysisSnapshot:
        """Atomically persist a completed canonical AnalysisResult as an immutable snapshot (async)."""
        snapshot, findings, deductions, comps, edges = _build_snapshot_entities(
            repository_id, result, config_dict
        )
        db.add(snapshot)
        for f in findings:
            db.add(f)
        for d in deductions:
            db.add(d)
        for c in comps:
            db.add(c)
        for e in edges:
            db.add(e)

        # Atomic commit
        await db.commit()
        loaded = await PersistenceService.get_analysis_snapshot(db, repository_id, snapshot.id)
        return loaded or snapshot

    @staticmethod
    def save_analysis_snapshot_sync(
        db: Session,
        repository_id: str,
        result: AnalysisResult,
        config_dict: Optional[dict[str, Any]] = None,
    ) -> AnalysisSnapshot:
        """Atomically persist a completed canonical AnalysisResult as an immutable snapshot (sync for Celery)."""
        snapshot, findings, deductions, comps, edges = _build_snapshot_entities(
            repository_id, result, config_dict
        )
        db.add(snapshot)
        for f in findings:
            db.add(f)
        for d in deductions:
            db.add(d)
        for c in comps:
            db.add(c)
        for e in edges:
            db.add(e)

        # Atomic sync commit
        db.commit()
        loaded = PersistenceService.get_analysis_snapshot_sync(db, repository_id, snapshot.id)
        return loaded or snapshot

    @staticmethod
    def get_analysis_snapshot_sync(
        db: Session,
        repository_id: str,
        analysis_id: str,
    ) -> Optional[AnalysisSnapshot]:
        """Fetch a specific historical snapshot synchronously enforcing repository boundary isolation."""
        query = (
            select(AnalysisSnapshot)
            .where(
                AnalysisSnapshot.id == analysis_id,
                AnalysisSnapshot.repository_id == repository_id,
            )
            .options(
                selectinload(AnalysisSnapshot.findings),
                selectinload(AnalysisSnapshot.deductions),
                selectinload(AnalysisSnapshot.components),
                selectinload(AnalysisSnapshot.component_edges),
            )
        )
        return db.execute(query).scalar_one_or_none()


    @staticmethod
    async def get_analysis_snapshot(
        db: AsyncSession,
        repository_id: str,
        analysis_id: str,
    ) -> Optional[AnalysisSnapshot]:
        """Fetch a specific historical snapshot enforcing repository boundary isolation."""
        query = (
            select(AnalysisSnapshot)
            .where(
                AnalysisSnapshot.id == analysis_id,
                AnalysisSnapshot.repository_id == repository_id,
            )
            .options(
                selectinload(AnalysisSnapshot.findings),
                selectinload(AnalysisSnapshot.deductions),
                selectinload(AnalysisSnapshot.components),
                selectinload(AnalysisSnapshot.component_edges),
            )
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_analysis_snapshots(
        db: AsyncSession,
        repository_id: str,
        skip: int = 0,
        limit: int = 20,
    ) -> tuple[list[AnalysisSnapshot], int]:
        """List historical analyses for a repository, paginated and ordered chronologically."""
        # Total count for repository
        count_query = (
            select(func.count(AnalysisSnapshot.id))
            .where(AnalysisSnapshot.repository_id == repository_id)
        )
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        # Paginated items
        items_query = (
            select(AnalysisSnapshot)
            .where(AnalysisSnapshot.repository_id == repository_id)
            .order_by(AnalysisSnapshot.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        items_result = await db.execute(items_query)
        snapshots = list(items_result.scalars().all())

        return snapshots, total

    @staticmethod
    def reconstruct_analysis_dto(
        snapshot: AnalysisSnapshot,
        repo_path: Path,
        repo_name: str,
    ) -> AnalysisResultDTO:
        """Reconstruct a canonical AnalysisResultDTO from an immutable AnalysisSnapshot."""
        # 1. Reconstruct Findings
        finding_dtos: list[FindingDTO] = []
        for f in snapshot.findings:
            loc_dto = LocationDTO(
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                column_start=f.column_start,
                column_end=f.column_end,
            )
            evidence_dto = EvidenceDTO(
                snippet=f.snippet,
                language=f.language or "plaintext",
                highlight_lines=[f.line_start] if f.line_start else [],
            )
            finding_dtos.append(
                FindingDTO(
                    id=f.finding_uuid,
                    rule_id=f.rule_id,
                    rule_name=f.rule_name,
                    message=f.message,
                    category=f.category,
                    severity=f.severity,
                    confidence=f.confidence,
                    description=f.description,
                    remediation=f.remediation,
                    location=loc_dto,
                    evidence=evidence_dto,
                    cwe_id=f.cwe_id,
                    owasp_category=f.owasp_category,
                    dataflow_evidence=f.evidence if (f.evidence and f.evidence.get("flow_type") in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT")) else None,
                )
            )

        # 2. Reconstruct Health Score & Deductions
        arch_deductions: list[DeductionDTO] = []
        sec_deductions: list[DeductionDTO] = []
        for d in snapshot.deductions:
            dto = DeductionDTO(
                category=d.category,
                rule_id=d.rule_id,
                points_deducted=d.points_deducted,
                reason=d.reason,
                finding_id=d.finding_id,
                item_count=d.item_count,
            )
            if d.category == "SECURITY":
                sec_deductions.append(dto)
            else:
                arch_deductions.append(dto)

        health_dto = HealthScoreDTO(
            overall_score=snapshot.overall_score,
            overall_grade=snapshot.overall_grade,
            architecture_health=SubScoreDTO(
                score=snapshot.architecture_score,
                grade=snapshot.architecture_grade,
                deductions=arch_deductions,
            ),
            security_posture=SubScoreDTO(
                score=snapshot.security_score,
                grade=snapshot.security_grade,
                deductions=sec_deductions,
            ),
            total_deductions_count=snapshot.total_deductions_count,
            summary=snapshot.health_summary,
        )

        # 3. Reconstruct Component Graph
        comp_graph_dto: Optional[ComponentGraphDTO] = None
        if snapshot.components:
            node_dtos = [
                ComponentNodeDTO(
                    id=n.component_id,
                    name=n.name,
                    path=n.path,
                    layer=n.layer,
                    coupling=ComponentCouplingDTO(
                        afferent=n.afferent_coupling,
                        efferent=n.efferent_coupling,
                        instability=n.instability,
                        total_loc=n.total_loc,
                        file_count=n.file_count,
                        betweenness_centrality=getattr(n, "betweenness_centrality", 0.0) or 0.0,
                        in_degree_centrality=getattr(n, "in_degree_centrality", 0.0) or 0.0,
                        out_degree_centrality=getattr(n, "out_degree_centrality", 0.0) or 0.0,
                    ),
                    files=n.files or [],
                )
                for n in snapshot.components
            ]
            edge_dtos = [
                ComponentEdgeDTO(
                    id=e.edge_id,
                    source=e.source_component_id,
                    target=e.target_component_id,
                    weight=e.weight,
                    is_cycle=e.is_circular,
                )
                for e in snapshot.component_edges
            ]

            # Reconstruct component cycle paths from finding evidence
            cycles: list[list[str]] = []
            for f in snapshot.findings:
                if f.rule_id == "ARC-006" and f.evidence and "cycle_components" in f.evidence:
                    comp_cycle = f.evidence.get("cycle_components", [])
                    if comp_cycle and comp_cycle not in cycles:
                        cycles.append(comp_cycle)

            comp_graph_dto = ComponentGraphDTO(
                nodes=node_dtos,
                edges=edge_dtos,
                circular_components_count=snapshot.circular_components_count,
                cycles=cycles,
            )

        # 4. Reconstruct Summary
        summary_dto = AnalysisSummaryDTO(
            total_findings=snapshot.total_findings,
            critical=snapshot.critical_count,
            high=snapshot.high_count,
            medium=snapshot.medium_count,
            low=snapshot.low_count,
            info=snapshot.info_count,
            total_modules=len(snapshot.components) if snapshot.components else 0,
            circular_dependencies_count=snapshot.circular_dependencies_count,
            total_files=snapshot.total_files,
            total_loc=snapshot.total_loc,
            duration_seconds=snapshot.duration_seconds,
        )

        # 5. Reconstruct Diagnostics
        diagnostics_dtos: list[DiagnosticDTO] = []
        if snapshot.diagnostics_payload:
            for d in snapshot.diagnostics_payload:
                diagnostics_dtos.append(
                    DiagnosticDTO(
                        file_path=d.get("file_path", ""),
                        source_module=d.get("source_module", ""),
                        line_number=d.get("line_number"),
                        diagnostic_type=d.get("diagnostic_type", "UNKNOWN"),
                        message=d.get("message", ""),
                        reason=d.get("reason", ""),
                        assigned_category=d.get("assigned_category", "UNRESOLVED"),
                    )
                )

        return AnalysisResultDTO(
            id=snapshot.id,
            status=snapshot.status,
            repository_path=str(repo_path),
            repository_name=repo_name,
            summary=summary_dto,
            health=health_dto,
            findings=finding_dtos,
            component_graph=comp_graph_dto,
            diagnostics=diagnostics_dtos,
            call_graph_summary=snapshot.call_graph_summary,
        )
