"""Longitudinal trend service computing historical trajectories, defect velocity, and drift."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.component import ComponentSnapshot
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.schemas.trend import (
    ComponentDriftSummary,
    DefectVelocityPoint,
    LongitudinalTrendDTO,
    TimelinePoint,
)


def _normalize_finding_key(rule_id: str, file_path: str, snippet: Optional[str], line_start: Optional[int]) -> str:
    """Compute signature string for finding identity across snapshots."""
    norm_path = (file_path or "").replace("\\", "/").strip("/").lower()
    norm_snippet = " ".join((snippet or "").strip().split())
    if norm_snippet:
        return f"{rule_id}::{norm_path}::{norm_snippet}"
    return f"{rule_id}::{norm_path}::{line_start or 0}"


class TrendService:
    """Service computing longitudinal quality intelligence across historical snapshots."""

    @staticmethod
    async def get_repository_trends(
        db: AsyncSession,
        repository_id: str,
        branch: Optional[str] = None,
        days: Optional[int] = None,
        limit: int = 50,
    ) -> LongitudinalTrendDTO:
        """Compute longitudinal quality trajectory for a registered repository."""
        # 1. Verify repository existence
        repo_result = await db.execute(select(Repository).where(Repository.id == repository_id))
        repo = repo_result.scalar_one_or_none()
        if not repo:
            raise ValueError(f"Repository '{repository_id}' not found")

        # 2. Query historical snapshots in window
        query = select(AnalysisSnapshot).where(AnalysisSnapshot.repository_id == repository_id)

        if branch:
            query = query.where(AnalysisSnapshot.branch == branch)

        if days is not None and days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            query = query.where(AnalysisSnapshot.created_at >= cutoff)

        # Order by created_at desc with limit, then reverse to chronological order
        query = query.order_by(AnalysisSnapshot.created_at.desc()).limit(max(1, limit))
        result = await db.execute(query)
        snapshots_desc = list(result.scalars().all())

        if not snapshots_desc:
            return LongitudinalTrendDTO(
                repository_id=repository_id,
                branch=branch,
                total_snapshots=0,
                window_days=days,
                health_trajectory=[],
                defect_velocity=[],
                severity_trajectories={
                    "CRITICAL": [],
                    "HIGH": [],
                    "MEDIUM": [],
                    "LOW": [],
                    "INFO": [],
                },
                component_drift=[],
                overall_health_delta=0.0,
                defect_burndown_rate=0.0,
            )

        snapshots = list(reversed(snapshots_desc))
        snapshot_ids = [s.id for s in snapshots]

        # 3. Build TimelinePoints and Severity Trajectories
        timeline_points: list[TimelinePoint] = []
        crit_traj: list[int] = []
        high_traj: list[int] = []
        med_traj: list[int] = []
        low_traj: list[int] = []
        info_traj: list[int] = []

        for s in snapshots:
            pt = TimelinePoint(
                snapshot_id=s.id,
                created_at=s.created_at,
                commit_hash=s.commit_hash,
                branch=s.branch,
                overall_score=round(s.overall_score, 2),
                architecture_score=round(s.architecture_score, 2),
                security_score=round(s.security_score, 2),
                overall_grade=s.overall_grade,
                total_findings=s.total_findings,
                critical_count=s.critical_count,
                high_count=s.high_count,
                medium_count=s.medium_count,
                low_count=s.low_count,
                info_count=s.info_count,
            )
            timeline_points.append(pt)
            crit_traj.append(s.critical_count)
            high_traj.append(s.high_count)
            med_traj.append(s.medium_count)
            low_traj.append(s.low_count)
            info_traj.append(s.info_count)

        severity_trajectories = {
            "CRITICAL": crit_traj,
            "HIGH": high_traj,
            "MEDIUM": med_traj,
            "LOW": low_traj,
            "INFO": info_traj,
        }

        # 4. Compute Defect Velocity between successive snapshots
        findings_query = select(
            FindingSnapshot.snapshot_id,
            FindingSnapshot.rule_id,
            FindingSnapshot.file_path,
            FindingSnapshot.line_start,
            FindingSnapshot.snippet,
        ).where(FindingSnapshot.snapshot_id.in_(snapshot_ids))
        findings_res = await db.execute(findings_query)
        raw_findings = findings_res.all()

        findings_by_snapshot: dict[str, set[str]] = {sid: set() for sid in snapshot_ids}
        for row in raw_findings:
            sid, rule_id, file_path, line_start, snippet = row
            key = _normalize_finding_key(rule_id, file_path, snippet, line_start)
            findings_by_snapshot[sid].add(key)

        defect_velocity: list[DefectVelocityPoint] = []
        total_new_defects = 0
        total_resolved_defects = 0

        for i, snap in enumerate(snapshots):
            curr_keys = findings_by_snapshot.get(snap.id, set())
            if i == 0:
                new_count = len(curr_keys)
                resolved_count = 0
            else:
                prev_keys = findings_by_snapshot.get(snapshots[i - 1].id, set())
                new_count = len(curr_keys - prev_keys)
                resolved_count = len(prev_keys - curr_keys)

            net = new_count - resolved_count
            total_new_defects += new_count
            total_resolved_defects += resolved_count

            defect_velocity.append(
                DefectVelocityPoint(
                    snapshot_id=snap.id,
                    created_at=snap.created_at,
                    new_defects=new_count,
                    resolved_defects=resolved_count,
                    net_change=net,
                )
            )

        # Defect burndown rate
        if total_new_defects > 0:
            burndown_rate = round(total_resolved_defects / total_new_defects, 3)
        else:
            burndown_rate = 1.0 if total_resolved_defects == 0 else 0.0

        # Overall health delta (latest vs earliest in window)
        health_delta = round(snapshots[-1].overall_score - snapshots[0].overall_score, 2)

        # 5. Component Architectural Drift
        earliest_id = snapshots[0].id
        latest_id = snapshots[-1].id

        comp_query = select(ComponentSnapshot).where(
            ComponentSnapshot.snapshot_id.in_([earliest_id, latest_id])
        )
        comp_res = await db.execute(comp_query)
        all_comps = list(comp_res.scalars().all())

        baseline_comps = {c.component_id: c for c in all_comps if c.snapshot_id == earliest_id}
        latest_comps = {c.component_id: c for c in all_comps if c.snapshot_id == latest_id}

        component_drift: list[ComponentDriftSummary] = []
        for c_id, curr_comp in latest_comps.items():
            base_comp = baseline_comps.get(c_id)
            base_inst = base_comp.instability if base_comp else None
            curr_inst = curr_comp.instability
            drift = round(curr_inst - (base_inst if base_inst is not None else curr_inst), 3)

            component_drift.append(
                ComponentDriftSummary(
                    component_id=c_id,
                    name=curr_comp.name,
                    baseline_instability=base_inst,
                    current_instability=curr_inst,
                    instability_drift=drift,
                    current_centrality=getattr(curr_comp, "betweenness_centrality", 0.0),
                )
            )

        # Sort component drift by absolute drift descending
        component_drift.sort(key=lambda c: abs(c.instability_drift), reverse=True)

        return LongitudinalTrendDTO(
            repository_id=repository_id,
            branch=branch,
            total_snapshots=len(snapshots),
            window_days=days,
            health_trajectory=timeline_points,
            defect_velocity=defect_velocity,
            severity_trajectories=severity_trajectories,
            component_drift=component_drift[:15],
            overall_health_delta=health_delta,
            defect_burndown_rate=burndown_rate,
        )
