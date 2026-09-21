"""Differential baseline comparison endpoint for CodeSentinel API (Phase 9)."""

import json
from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException, status
from starlette.concurrency import run_in_threadpool

from analyzer.comparison.diff import BaselineComparator
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult
from backend.app.api.v1.endpoints.analyze import infer_language
from backend.app.core.security import validate_repository_path
from backend.app.schemas.analysis import EvidenceDTO, FindingDTO, LocationDTO
from backend.app.schemas.comparison import (
    CompareRequest,
    ComparisonResponseDTO,
    ComparisonSummaryDTO,
    ComponentDeltaDTO,
    DifferentialFindingDTO,
    HealthDeltaDTO,
)

router = APIRouter()


def _finding_to_dto(f: Finding) -> FindingDTO:
    """Transform a domain Finding into a FindingDTO."""
    loc_dto = LocationDTO(
        file_path=f.location.file_path,
        line_start=f.location.line_start or 1,
        line_end=f.location.line_end or f.location.line_start or 1,
        column_start=f.location.col_start,
        column_end=f.location.col_end,
    )
    evidence_dto = EvidenceDTO(
        snippet=f.code_snippet,
        language=infer_language(f.location.file_path),
        highlight_lines=[f.location.line_start] if f.location.line_start else [1],
    )
    return FindingDTO(
        id=f.id,
        rule_id=f.rule_id,
        rule_name=f.rule_name,
        message=f.message or f.rule_name,
        category=f.category.value if hasattr(f.category, "value") else str(f.category),
        severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
        description=f.explanation or f.description,
        remediation=f.remediation,
        location=loc_dto,
        evidence=evidence_dto,
        cwe_id=f.cwe_id,
        owasp_category=f.owasp_category,
    )


def _load_result(json_data: dict[str, Any] | None, path_str: str | None, label: str) -> AnalysisResult:
    """Load or analyze an AnalysisResult from either JSON dictionary or filesystem path."""
    if json_data is not None:
        try:
            return AnalysisResult(**json_data)
        except Exception as err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid {label} AnalysisResult JSON structure: {err}",
            )

    if not path_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Must provide either '{label}_json' or '{label}_path'",
        )

    target = Path(path_str).resolve()
    if not target.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{label.capitalize()} path does not exist: {path_str}",
        )

    if target.is_file():
        try:
            raw_text = target.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            return AnalysisResult(**data)
        except Exception as err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to parse {label} JSON report file '{path_str}': {err}",
            )
    elif target.is_dir():
        canonical_dir = validate_repository_path(str(target))
        pipeline = AnalysisPipeline()
        return pipeline.run(canonical_dir)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {label} path type: {path_str}",
        )


@router.post(
    "/compare",
    response_model=ComparisonResponseDTO,
    summary="Compare baseline vs current analysis",
    description=(
        "Performs differential static analysis comparison between a historical baseline "
        "and a current run. Accurately flags NEW (regressions), RESOLVED (fixes), and "
        "calculates exact health and instability deltas."
    ),
)
async def compare_analysis(request: CompareRequest) -> ComparisonResponseDTO:
    """Compare baseline and current codebase states or reports."""
    # 1. Resolve baseline and current results (in worker thread pool to avoid blocking)
    def _execute_comparison() -> ComparisonResponseDTO:
        baseline_res = _load_result(request.baseline_json, request.baseline_path, "baseline")
        current_res = _load_result(request.current_json, request.current_path, "current")

        domain_comparison = BaselineComparator.compare(current=current_res, baseline=baseline_res)

        # 2. Map findings
        diff_finding_dtos: list[DifferentialFindingDTO] = [
            DifferentialFindingDTO(
                finding=_finding_to_dto(df.finding),
                transition=df.transition.value if hasattr(df.transition, "value") else str(df.transition),
                baseline_finding_id=df.baseline_finding_id,
                match_method=df.match_method,
                detail=df.detail,
            )
            for df in domain_comparison.findings
        ]

        # 3. Map health delta
        health_delta_dto: HealthDeltaDTO | None = None
        if domain_comparison.health_delta is not None:
            hd = domain_comparison.health_delta
            health_delta_dto = HealthDeltaDTO(
                score_delta=hd.score_delta,
                baseline_score=hd.baseline_score,
                current_score=hd.current_score,
                baseline_grade=hd.baseline_grade,
                current_grade=hd.current_grade,
                grade_changed=hd.grade_changed,
                architecture_score_delta=hd.architecture_score_delta,
                security_score_delta=hd.security_score_delta,
            )

        # 4. Map component delta
        comp_delta_dto: ComponentDeltaDTO | None = None
        if domain_comparison.component_delta is not None:
            cd = domain_comparison.component_delta
            comp_delta_dto = ComponentDeltaDTO(
                new_components=cd.new_components,
                removed_components=cd.removed_components,
                instability_deltas=cd.instability_deltas,
                new_cycles=cd.new_cycles,
                resolved_cycles=cd.resolved_cycles,
            )

        # 5. Map summary
        s = domain_comparison.summary
        summary_dto = ComparisonSummaryDTO(
            total_current=s.total_current,
            total_baseline=s.total_baseline,
            new_count=s.new_count,
            resolved_count=s.resolved_count,
            unchanged_count=s.unchanged_count,
            modified_count=s.modified_count,
            new_by_severity=s.new_by_severity,
            resolved_by_severity=s.resolved_by_severity,
        )

        return ComparisonResponseDTO(
            baseline_id=domain_comparison.baseline_id,
            current_id=domain_comparison.current_id,
            baseline_commit=domain_comparison.baseline_commit,
            current_commit=domain_comparison.current_commit,
            compared_at=domain_comparison.compared_at.isoformat(),
            summary=summary_dto,
            findings=diff_finding_dtos,
            health_delta=health_delta_dto,
            component_delta=comp_delta_dto,
        )

    return await run_in_threadpool(_execute_comparison)
