"""Finding reconciliation and line-shift relocation engine (Phase 21)."""

import json
from typing import Any, Optional

from analyzer.incremental.models import FindingReconciliationState
from analyzer.models.findings import Finding
from analyzer.rules.engine import deduplicate_findings


def _norm_path(p: str) -> str:
    return p.replace("\\", "/").strip("/").lower()


def _norm_snippet(s: Optional[str]) -> str:
    if not s:
        return ""
    return " ".join(s.strip().split())


class FindingReconciler:
    """Reconciles cached findings with newly computed findings during incremental analysis."""

    @classmethod
    def reconcile(
        cls,
        previous_findings: list[Finding],
        newly_computed_findings: list[Finding],
        affected_files: set[str],
        deleted_files: set[str],
    ) -> tuple[list[Finding], dict[str, int]]:
        """Reconcile previous findings against freshly re-analyzed units.
        
        Rules:
        - Findings from unaffected files (not in affected_files and not in deleted_files) are REUSED.
        - Findings from deleted_files are RESOLVED.
        - Findings from affected_files that re-appear are RECOMPUTED.
        - Findings from affected_files appearing for the first time are NEW.
        """
        norm_affected = {_norm_path(f) for f in affected_files}
        norm_deleted = {_norm_path(f) for f in deleted_files}

        reused_findings: list[Finding] = []
        resolved_count = 0
        recomputed_count = 0
        new_count = 0

        prev_by_id = {f.id: f for f in previous_findings}

        for f in previous_findings:
            f_path = _norm_path(f.location.file_path)
            if f_path in norm_deleted:
                resolved_count += 1
            elif f_path not in norm_affected:
                reused_findings.append(f)

        for f in newly_computed_findings:
            if f.id in prev_by_id:
                recomputed_count += 1
            else:
                new_count += 1

        combined = reused_findings + newly_computed_findings
        final_findings = deduplicate_findings(combined)

        counts = {
            FindingReconciliationState.REUSED.value: len(reused_findings),
            FindingReconciliationState.RECOMPUTED.value: recomputed_count,
            FindingReconciliationState.NEW.value: new_count,
            FindingReconciliationState.RESOLVED.value: resolved_count,
        }

        return final_findings, counts
