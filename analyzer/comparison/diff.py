"""Deterministic baseline comparison engine for CodeSentinel differential analysis (Phase 9)."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from analyzer.models.comparison import (
    ComparisonResult,
    ComparisonSummary,
    ComponentGraphDelta,
    DifferentialFinding,
    FindingTransition,
    HealthDelta,
)
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult


def _norm_path(p: str) -> str:
    """Normalize file path for cross-platform comparison."""
    return p.replace("\\", "/").strip("/").lower()


def _norm_snippet(s: Optional[str]) -> str:
    """Normalize code snippet by condensing whitespace."""
    if not s:
        return ""
    return " ".join(s.strip().split())


class BaselineComparator:
    """Deterministic comparison engine comparing current analysis against a baseline run."""

    @staticmethod
    def compare(
        current: AnalysisResult,
        baseline: AnalysisResult,
    ) -> ComparisonResult:
        """Compare current AnalysisResult against a baseline AnalysisResult.
        
        Performs multi-tier signature matching:
        1. Exact signature: (rule_id, path, line_start, snippet)
        2. Fuzzy snippet: (rule_id, path, snippet) across line shifts
        3. Fuzzy location: (rule_id, path, line_start) across minor snippet changes
        4. Explicit ID match: fallback if IDs match
        """
        current_findings: list[Finding] = current.security_findings + current.architecture_findings
        baseline_findings: list[Finding] = baseline.security_findings + baseline.architecture_findings

        # Index baseline findings
        baseline_by_id: dict[str, Finding] = {f.id: f for f in baseline_findings}
        
        # Multi-maps for baseline signatures
        exact_sig_map: dict[tuple, list[Finding]] = defaultdict(list)
        snippet_sig_map: dict[tuple, list[Finding]] = defaultdict(list)
        location_sig_map: dict[tuple, list[Finding]] = defaultdict(list)

        for f in baseline_findings:
            p = _norm_path(f.location.file_path)
            snip = _norm_snippet(f.code_snippet)
            line = f.location.line_start or 1

            exact_sig_map[(f.rule_id, p, line, snip)].append(f)
            snippet_sig_map[(f.rule_id, p, snip)].append(f)
            location_sig_map[(f.rule_id, p, line)].append(f)

        matched_baseline_ids: set[str] = set()
        diff_findings: list[DifferentialFinding] = []

        # Compare current findings against indexed baseline
        for curr_f in current_findings:
            curr_p = _norm_path(curr_f.location.file_path)
            curr_snip = _norm_snippet(curr_f.code_snippet)
            curr_line = curr_f.location.line_start or 1

            matched_base: Optional[Finding] = None
            match_method: Optional[str] = None
            transition: FindingTransition = FindingTransition.NEW

            # Tier 1: Exact signature match
            exact_key = (curr_f.rule_id, curr_p, curr_line, curr_snip)
            candidates = [f for f in exact_sig_map.get(exact_key, []) if f.id not in matched_baseline_ids]
            if candidates:
                matched_base = candidates[0]
                match_method = "exact_signature"
                transition = FindingTransition.UNCHANGED

            # Tier 2: Fuzzy snippet match (same rule & snippet, shifted line number)
            if not matched_base and curr_snip:
                snip_key = (curr_f.rule_id, curr_p, curr_snip)
                candidates = [f for f in snippet_sig_map.get(snip_key, []) if f.id not in matched_baseline_ids]
                if candidates:
                    matched_base = candidates[0]
                    match_method = "fuzzy_snippet"
                    # If lines differ, consider it MODIFIED
                    base_line = matched_base.location.line_start or 1
                    transition = FindingTransition.UNCHANGED if base_line == curr_line else FindingTransition.MODIFIED

            # Tier 3: Fuzzy location match (same rule & file & line, snippet modified)
            if not matched_base:
                loc_key = (curr_f.rule_id, curr_p, curr_line)
                candidates = [f for f in location_sig_map.get(loc_key, []) if f.id not in matched_baseline_ids]
                if candidates:
                    matched_base = candidates[0]
                    match_method = "fuzzy_location"
                    transition = FindingTransition.MODIFIED

            # Tier 4: Explicit ID match fallback
            if not matched_base and curr_f.id in baseline_by_id and curr_f.id not in matched_baseline_ids:
                matched_base = baseline_by_id[curr_f.id]
                match_method = "id"
                transition = FindingTransition.UNCHANGED

            if matched_base:
                matched_baseline_ids.add(matched_base.id)
                diff_findings.append(
                    DifferentialFinding(
                        finding=curr_f,
                        transition=transition,
                        baseline_finding_id=matched_base.id,
                        match_method=match_method,
                    )
                )
            else:
                # Newly introduced finding (regression)
                diff_findings.append(
                    DifferentialFinding(
                        finding=curr_f,
                        transition=FindingTransition.NEW,
                        baseline_finding_id=None,
                        match_method=None,
                    )
                )

        # Baseline findings not matched in current are RESOLVED
        for base_f in baseline_findings:
            if base_f.id not in matched_baseline_ids:
                diff_findings.append(
                    DifferentialFinding(
                        finding=base_f,
                        transition=FindingTransition.RESOLVED,
                        baseline_finding_id=base_f.id,
                        match_method=None,
                        detail="Defect resolved in current codebase.",
                    )
                )

        # Deterministic ordering for diff_findings
        transition_priority = {
            FindingTransition.NEW: 0,
            FindingTransition.MODIFIED: 1,
            FindingTransition.UNCHANGED: 2,
            FindingTransition.RESOLVED: 3,
        }
        diff_findings.sort(
            key=lambda df: (
                transition_priority.get(df.transition, 99),
                df.finding.location.file_path,
                df.finding.location.line_start or 0,
                df.finding.rule_id,
                df.finding.id,
            )
        )

        # Calculate summary metrics
        new_count = sum(1 for df in diff_findings if df.transition == FindingTransition.NEW)
        resolved_count = sum(1 for df in diff_findings if df.transition == FindingTransition.RESOLVED)
        unchanged_count = sum(1 for df in diff_findings if df.transition == FindingTransition.UNCHANGED)
        modified_count = sum(1 for df in diff_findings if df.transition == FindingTransition.MODIFIED)

        new_by_severity: dict[str, int] = defaultdict(int)
        for df in diff_findings:
            if df.transition == FindingTransition.NEW:
                sev = df.finding.severity.value if hasattr(df.finding.severity, "value") else str(df.finding.severity)
                new_by_severity[sev] += 1

        resolved_by_severity: dict[str, int] = defaultdict(int)
        for df in diff_findings:
            if df.transition == FindingTransition.RESOLVED:
                sev = df.finding.severity.value if hasattr(df.finding.severity, "value") else str(df.finding.severity)
                resolved_by_severity[sev] += 1

        summary = ComparisonSummary(
            total_current=len(current_findings),
            total_baseline=len(baseline_findings),
            new_count=new_count,
            resolved_count=resolved_count,
            unchanged_count=unchanged_count,
            modified_count=modified_count,
            new_by_severity=dict(new_by_severity),
            resolved_by_severity=dict(resolved_by_severity),
        )

        # Calculate HealthDelta if both runs have health scoring
        health_delta: Optional[HealthDelta] = None
        if current.health is not None and baseline.health is not None:
            score_delta = round(current.health.overall_score - baseline.health.overall_score, 2)
            arch_delta = round(
                current.health.architecture_health.score - baseline.health.architecture_health.score, 2
            )
            sec_delta = round(
                current.health.security_posture.score - baseline.health.security_posture.score, 2
            )
            health_delta = HealthDelta(
                score_delta=score_delta,
                baseline_score=baseline.health.overall_score,
                current_score=current.health.overall_score,
                baseline_grade=baseline.health.overall_grade,
                current_grade=current.health.overall_grade,
                grade_changed=(baseline.health.overall_grade != current.health.overall_grade),
                architecture_score_delta=arch_delta,
                security_score_delta=sec_delta,
            )

        # Calculate ComponentGraphDelta if both runs have component graphs
        component_delta: Optional[ComponentGraphDelta] = None
        curr_cg = current.graph.component_graph
        base_cg = baseline.graph.component_graph
        if curr_cg is not None and base_cg is not None:
            curr_comps = {c.id: c for c in curr_cg.nodes}
            base_comps = {c.id: c for c in base_cg.nodes}

            new_comps = sorted(list(set(curr_comps.keys()) - set(base_comps.keys())))
            removed_comps = sorted(list(set(base_comps.keys()) - set(curr_comps.keys())))

            instability_deltas: dict[str, float] = {}
            for comp_id in sorted(set(curr_comps.keys()).intersection(set(base_comps.keys()))):
                c_inst = curr_comps[comp_id].metrics.instability
                b_inst = base_comps[comp_id].metrics.instability
                diff = round(c_inst - b_inst, 3)
                if abs(diff) > 0.001:
                    instability_deltas[comp_id] = diff

            # Compute cycle differences
            curr_cycles = [sorted(c.modules) for c in current.graph.circular_dependencies]
            base_cycles = [sorted(c.modules) for c in baseline.graph.circular_dependencies]
            new_cycles = [c for c in curr_cycles if c not in base_cycles]
            resolved_cycles = [c for c in base_cycles if c not in curr_cycles]

            component_delta = ComponentGraphDelta(
                new_components=new_comps,
                removed_components=removed_comps,
                instability_deltas=instability_deltas,
                new_cycles=new_cycles,
                resolved_cycles=resolved_cycles,
            )

        return ComparisonResult(
            baseline_id=baseline.id,
            current_id=current.id,
            baseline_commit=baseline.repository.commit_hash,
            current_commit=current.repository.commit_hash,
            compared_at=datetime.now(timezone.utc),
            summary=summary,
            findings=diff_findings,
            health_delta=health_delta,
            component_delta=component_delta,
        )
