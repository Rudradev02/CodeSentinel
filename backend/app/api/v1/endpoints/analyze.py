"""Synchronous codebase static analysis endpoint for CodeSentinel API."""

from pathlib import Path
from typing import Optional
from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.results import AnalysisResult
from backend.app.core.security import validate_repository_path
from backend.app.schemas.analysis import (
    AnalysisRequest,
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

router = APIRouter()


def infer_language(file_path: str) -> str:
    """Infer editor syntax language from source file extension."""
    ext = Path(file_path).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".md": "markdown",
        ".html": "html",
        ".css": "css",
        ".sh": "shell",
        ".sql": "sql",
    }
    return mapping.get(ext, "plaintext")


def map_result_to_dto(result: AnalysisResult, repo_path: Path) -> AnalysisResultDTO:
    """Adapt domain AnalysisResult into client-facing AnalysisResultDTO."""
    # 1. Transform findings
    all_findings = result.security_findings + result.architecture_findings
    finding_dtos: list[FindingDTO] = []

    for f in all_findings:
        lang = infer_language(f.location.file_path)
        loc_dto = LocationDTO(
            file_path=f.location.file_path,
            line_start=f.location.line_start,
            line_end=f.location.line_end,
            column_start=f.location.col_start,
            column_end=f.location.col_end,
        )
        evidence_dto = EvidenceDTO(
            snippet=f.code_snippet,
            language=lang,
            highlight_lines=[f.location.line_start] if f.location.line_start else [],
        )
        finding_dtos.append(
            FindingDTO(
                id=f.id,
                rule_id=f.rule_id,
                rule_name=f.rule_name,
                message=f.message or f.rule_name,
                category=f.category.value if hasattr(f.category, "value") else str(f.category),
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                description=f.description,
                remediation=f.remediation,
                location=loc_dto,
                evidence=evidence_dto,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
            )
        )

    # 2. Transform Health Scoring
    health_dto: Optional[HealthScoreDTO] = None
    if result.health:
        arch_deductions = [
            DeductionDTO(
                category=d.category,
                rule_id=d.rule_id,
                points_deducted=d.points_deducted,
                reason=d.reason,
                finding_id=d.finding_id,
                item_count=d.item_count,
            )
            for d in result.health.architecture_health.deductions
        ]
        sec_deductions = [
            DeductionDTO(
                category=d.category,
                rule_id=d.rule_id,
                points_deducted=d.points_deducted,
                reason=d.reason,
                finding_id=d.finding_id,
                item_count=d.item_count,
            )
            for d in result.health.security_posture.deductions
        ]

        health_dto = HealthScoreDTO(
            overall_score=result.health.overall_score,
            overall_grade=result.health.overall_grade,
            architecture_health=SubScoreDTO(
                score=result.health.architecture_health.score,
                grade=result.health.architecture_health.grade,
                deductions=arch_deductions,
            ),
            security_posture=SubScoreDTO(
                score=result.health.security_posture.score,
                grade=result.health.security_posture.grade,
                deductions=sec_deductions,
            ),
            total_deductions_count=result.health.total_deductions_count,
            summary=result.health.summary,
        )

    # 3. Transform Subsystem Component Graph
    comp_graph_dto: Optional[ComponentGraphDTO] = None
    if result.graph and result.graph.component_graph:
        cg = result.graph.component_graph
        node_dtos = [
            ComponentNodeDTO(
                id=n.id,
                name=n.id.split(".")[-1] if "." in n.id else n.id,
                path=n.path,
                layer=n.layer,
                coupling=ComponentCouplingDTO(
                    afferent=n.metrics.afferent_coupling,
                    efferent=n.metrics.efferent_coupling,
                    instability=n.metrics.instability,
                    total_loc=n.metrics.total_loc,
                    file_count=n.metrics.file_count,
                ),
                files=n.files,
            )
            for n in cg.nodes
        ]
        edge_dtos = [
            ComponentEdgeDTO(
                id=e.id,
                source=e.source,
                target=e.target,
                weight=e.weight,
                is_cycle=getattr(e, "is_circular", False),
            )
            for e in cg.edges
        ]

        # Collect component cycles from ARC-006 findings if present
        cycles: list[list[str]] = []
        for f in result.architecture_findings:
            if f.rule_id == "ARC-006" and "cycle_components" in f.evidence:
                comp_cycle = f.evidence.get("cycle_components", [])
                if comp_cycle and comp_cycle not in cycles:
                    cycles.append(comp_cycle)

        comp_graph_dto = ComponentGraphDTO(
            nodes=node_dtos,
            edges=edge_dtos,
            circular_components_count=cg.circular_components_count,
            cycles=cycles,
        )

    # 4. Summary & Counters
    summary_dto = AnalysisSummaryDTO(
        total_findings=len(finding_dtos),
        critical=result.security_summary.critical,
        high=result.security_summary.high + sum(1 for f in result.architecture_findings if f.severity.value == "HIGH"),
        medium=result.security_summary.medium + sum(1 for f in result.architecture_findings if f.severity.value == "MEDIUM"),
        low=result.security_summary.low + sum(1 for f in result.architecture_findings if f.severity.value == "LOW"),
        info=result.security_summary.info + sum(1 for f in result.architecture_findings if f.severity.value == "INFO"),
        total_modules=result.architecture_summary.total_modules,
        circular_dependencies_count=result.architecture_summary.circular_dependencies_count,
        total_files=result.repository.total_files,
        total_loc=result.repository.total_loc,
        duration_seconds=result.metadata.duration_seconds or 0.0,
    )

    # 5. Diagnostics
    diagnostic_dtos = [
        DiagnosticDTO(
            file_path=d.file_path,
            source_module=d.source_module,
            line_number=d.line_number,
            diagnostic_type=d.diagnostic_type,
            message=d.message,
            reason=d.reason,
            assigned_category=d.assigned_category,
        )
        for d in result.dependency_diagnostics
    ]

    return AnalysisResultDTO(
        id=result.id,
        status=result.status.value if hasattr(result.status, "value") else str(result.status),
        repository_path=str(repo_path),
        repository_name=result.repository.name,
        summary=summary_dto,
        health=health_dto,
        findings=finding_dtos,
        component_graph=comp_graph_dto,
        diagnostics=diagnostic_dtos,
    )


@router.post(
    "/analyze",
    response_model=AnalysisResultDTO,
    summary="Execute synchronous static analysis",
    description=(
        "Run an end-to-end static security and architecture audit on a local directory path. "
        "Strictly offline, deterministic, and safe with zero execution of analyzed code."
    ),
)
async def analyze_repository(request: AnalysisRequest) -> AnalysisResultDTO:
    """Analyze a local repository synchronously and return the canonical result."""
    # 1. Enforce local filesystem security boundary
    canonical_path = validate_repository_path(request.path)

    # 2. Build analysis configuration
    config_kwargs = {}
    if request.fail_on:
        config_kwargs["fail_on_severity"] = request.fail_on.upper()
    if request.enabled_rules:
        config_kwargs["enabled_rules"] = request.enabled_rules
    if request.disabled_rules:
        config_kwargs["disabled_rules"] = request.disabled_rules
    if request.max_component_depth:
        config_kwargs["max_component_depth"] = request.max_component_depth

    analysis_config = AnalysisConfig(**config_kwargs)

    # 3. Execute analysis pipeline synchronously in worker thread pool
    pipeline = AnalysisPipeline(analysis_config=analysis_config)
    result: AnalysisResult = await run_in_threadpool(
        pipeline.run,
        target_path=canonical_path,
        analysis_config=analysis_config,
    )

    # 4. Map domain result to serializable DTO
    return map_result_to_dto(result, canonical_path)
