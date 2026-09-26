"""Equivalence verification engine comparing full and incremental analysis outputs (Phase 21)."""

from collections import defaultdict
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from analyzer.incremental.reconciliation import _norm_path, _norm_snippet
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult


class EquivalenceDiscrepancyKind(str, Enum):
    """Categorization of discrepancies between full and incremental runs."""
    MISSING_FINDING = "MISSING_FINDING"           # Finding present in full but dropped by incremental
    PHANTOM_FINDING = "PHANTOM_FINDING"           # Finding in incremental that full proves absent
    RELOCATED_FINDING = "RELOCATED_FINDING"       # Same defect with shifted line/col coordinates
    METRIC_MISMATCH = "METRIC_MISMATCH"           # Discrepancy in architecture or health scores
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"       # Discrepancy in contract summary verification (Phase 22)
    COMPOSITION_MISMATCH = "COMPOSITION_MISMATCH" # Discrepancy in contract composition edges (Phase 22)


class EquivalenceResult(BaseModel):
    """Evaluation summary of equivalence between full and incremental results."""
    is_equivalent: bool
    discrepancies: list[str] = Field(default_factory=list)
    matched_findings_count: int = 0
    relocated_findings_count: int = 0
    missing_findings_count: int = 0
    phantom_findings_count: int = 0
    architecture_matched: bool = True
    health_matched: bool = True
    contracts_matched: bool = True
    composition_matched: bool = True


class EquivalenceChecker:
    """Verifies that an incremental analysis produces the identical canonical result as full analysis."""

    @classmethod
    def compare(
        cls,
        full_result: AnalysisResult,
        incremental_result: AnalysisResult,
        verify_contracts: bool = False,
        verify_composition: bool = False,
    ) -> EquivalenceResult:
        """Compare full and incremental AnalysisResult instances."""
        full_findings: list[Finding] = full_result.security_findings + full_result.architecture_findings
        inc_findings: list[Finding] = incremental_result.security_findings + incremental_result.architecture_findings

        full_by_id = {f.id: f for f in full_findings}
        inc_by_id = {f.id: f for f in inc_findings}

        discrepancies: list[str] = []
        matched_count = 0
        relocated_count = 0

        # Exact ID matching
        common_ids = set(full_by_id.keys()) & set(inc_by_id.keys())
        matched_count += len(common_ids)

        unmatched_full_ids = set(full_by_id.keys()) - common_ids
        unmatched_inc_ids = set(inc_by_id.keys()) - common_ids

        # Relocation matching (same rule, path, snippet across line shifts)
        relocated_full = set()
        relocated_inc = set()

        inc_by_sig: dict[tuple, list[Finding]] = defaultdict(list)
        for inc_id in unmatched_inc_ids:
            f = inc_by_id[inc_id]
            sig = (f.rule_id, _norm_path(f.location.file_path), _norm_snippet(f.code_snippet))
            inc_by_sig[sig].append(f)

        for full_id in unmatched_full_ids:
            f = full_by_id[full_id]
            sig = (f.rule_id, _norm_path(f.location.file_path), _norm_snippet(f.code_snippet))
            candidates = inc_by_sig.get(sig, [])
            if candidates:
                matched_cand = candidates.pop(0)
                relocated_full.add(full_id)
                relocated_inc.add(matched_cand.id)
                relocated_count += 1

        missing_ids = unmatched_full_ids - relocated_full
        phantom_ids = unmatched_inc_ids - relocated_inc

        for mid in sorted(missing_ids):
            f = full_by_id[mid]
            discrepancies.append(
                f"MISSING: [{f.rule_id}] {f.location.file_path}:{f.location.line_start} (id: {mid})"
            )

        for pid in sorted(phantom_ids):
            f = inc_by_id[pid]
            discrepancies.append(
                f"PHANTOM: [{f.rule_id}] {f.location.file_path}:{f.location.line_start} (id: {pid})"
            )

        # Compare architecture metrics
        arch_matched = True
        if full_result.architecture_summary and incremental_result.architecture_summary:
            f_arch = full_result.architecture_summary
            i_arch = incremental_result.architecture_summary
            if (
                f_arch.total_modules != i_arch.total_modules
                or f_arch.circular_dependencies_count != i_arch.circular_dependencies_count
                or f_arch.god_modules_count != i_arch.god_modules_count
            ):
                arch_matched = False
                discrepancies.append(
                    f"METRIC_MISMATCH: Arch metrics differ: "
                    f"full({f_arch.total_modules}m, {f_arch.circular_dependencies_count}c, {f_arch.god_modules_count}g) vs "
                    f"inc({i_arch.total_modules}m, {i_arch.circular_dependencies_count}c, {i_arch.god_modules_count}g)"
                )

        # Compare health scores
        health_matched = True
        if full_result.health and incremental_result.health:
            f_health = full_result.health
            i_health = incremental_result.health
            if (
                round(f_health.overall_score, 2) != round(i_health.overall_score, 2)
                or f_health.overall_grade != i_health.overall_grade
            ):
                health_matched = False
                discrepancies.append(
                    f"METRIC_MISMATCH: Health score differs: full({f_health.overall_score}) vs inc({i_health.overall_score})"
                )

        # Phase 22: Contract Equivalence Verification
        contracts_matched = True
        if verify_contracts:
            f_cg = full_result.call_graph_summary or {}
            i_cg = incremental_result.call_graph_summary or {}
            f_contracts = f_cg.get("contracts")
            i_contracts = i_cg.get("contracts")
            if f_contracts != i_contracts:
                contracts_matched = False
                discrepancies.append(
                    f"CONTRACT_MISMATCH: Function contracts differ between full ({f_contracts}) and incremental ({i_contracts})"
                )

        # Phase 22: Composition Equivalence Verification
        composition_matched = True
        if verify_composition:
            f_cg = full_result.call_graph_summary or {}
            i_cg = incremental_result.call_graph_summary or {}
            f_comp = f_cg.get("composition")
            i_comp = i_cg.get("composition")
            if f_comp != i_comp:
                composition_matched = False
                discrepancies.append(
                    f"COMPOSITION_MISMATCH: Composition edges differ between full ({f_comp}) and incremental ({i_comp})"
                )

        is_equiv = (
            len(missing_ids) == 0
            and len(phantom_ids) == 0
            and arch_matched
            and health_matched
            and contracts_matched
            and composition_matched
        )

        return EquivalenceResult(
            is_equivalent=is_equiv,
            discrepancies=discrepancies,
            matched_findings_count=matched_count,
            relocated_findings_count=relocated_count,
            missing_findings_count=len(missing_ids),
            phantom_findings_count=len(phantom_ids),
            architecture_matched=arch_matched,
            health_matched=health_matched,
            contracts_matched=contracts_matched,
            composition_matched=composition_matched,
        )
