"""Deterministic Codebase Health & Risk Scoring Engine.

Calculates ArchitectureHealthScore and SecurityPostureScore on a 0.0 - 100.0 scale,
derives an executive letter grade (A-F), and records a transparent deduction log
allowing exact manual reconstruction of final scores.
"""

from typing import Optional
from analyzer.models.findings import Finding, FindingSeverity
from analyzer.models.results import CodebaseHealth, ScoreDeduction, SubScore

SEVERITY_DEDUCTIONS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 25.0,
    FindingSeverity.HIGH: 15.0,
    FindingSeverity.MEDIUM: 5.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.INFO: 0.0,
}

MAX_DEDUCTION_PER_RULE: float = 45.0


def calculate_letter_grade(score: float) -> str:
    """Map numeric score (0.0 - 100.0) to standard letter grade."""
    if score >= 90.0:
        return "A"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C"
    if score >= 60.0:
        return "D"
    return "F"


class HealthScoreCalculator:
    """Calculates deterministic codebase health, architecture rating, and security posture."""

    @staticmethod
    def calculate_sub_score(
        findings: list[Finding],
        category: str,
    ) -> SubScore:
        """Calculate sub-score for a specific category (SECURITY or ARCHITECTURE).
        
        Guarantees:
        - Non-double-counting: each finding contributes at most one deduction.
        - Deductions are capped at MAX_DEDUCTION_PER_RULE per rule ID.
        - Score is clamped to [0.0, 100.0].
        - Deductions are sorted deterministically.
        """
        base_score = 100.0
        deductions: list[ScoreDeduction] = []
        rule_deduction_totals: dict[str, float] = {}

        # Pre-sort findings for deterministic deduction ordering
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                f.location.file_path,
                f.location.line_start,
                f.location.col_start or 0,
                f.rule_id,
            )
        )

        for f in sorted_findings:
            raw_penalty = SEVERITY_DEDUCTIONS.get(f.severity, 0.0)
            if raw_penalty <= 0.0:
                continue

            current_rule_total = rule_deduction_totals.get(f.rule_id, 0.0)
            remaining_cap = max(0.0, MAX_DEDUCTION_PER_RULE - current_rule_total)

            if remaining_cap <= 0.0:
                # Rule cap reached; do not add further point deduction
                continue

            penalty = min(raw_penalty, remaining_cap)
            rule_deduction_totals[f.rule_id] = current_rule_total + penalty

            loc_str = f"{f.location.file_path}:{f.location.line_start}"
            reason = f"[{f.rule_id}] {f.severity.value} finding at {loc_str}: {f.message or f.rule_name}"

            deductions.append(
                ScoreDeduction(
                    category=category,
                    rule_id=f.rule_id,
                    points_deducted=penalty,
                    reason=reason,
                    finding_id=f.id,
                    item_count=1,
                )
            )

        total_deducted = sum(d.points_deducted for d in deductions)
        final_score = round(max(0.0, min(100.0, base_score - total_deducted)), 2)
        grade = calculate_letter_grade(final_score)

        # Sort deductions deterministically
        deductions.sort(key=lambda d: (d.category, d.rule_id, -d.points_deducted, d.reason))

        return SubScore(
            score=final_score,
            grade=grade,
            deductions=deductions,
        )

    @classmethod
    def compute(
        cls,
        security_findings: list[Finding],
        architecture_findings: list[Finding],
    ) -> CodebaseHealth:
        """Compute the full CodebaseHealth model.
        
        Composite formula: 55% Security Posture + 45% Architecture Health.
        """
        sec_sub = cls.calculate_sub_score(security_findings, category="SECURITY")
        arch_sub = cls.calculate_sub_score(architecture_findings, category="ARCHITECTURE")

        overall_score = round(0.55 * sec_sub.score + 0.45 * arch_sub.score, 2)
        overall_grade = calculate_letter_grade(overall_score)
        total_deductions = len(sec_sub.deductions) + len(arch_sub.deductions)

        summary = (
            f"Codebase Health Grade {overall_grade} ({overall_score:.2f}/100.00). "
            f"Architecture: {arch_sub.grade} ({arch_sub.score:.2f}), "
            f"Security: {sec_sub.grade} ({sec_sub.score:.2f}). "
            f"{len(architecture_findings)} architecture smell(s), {len(security_findings)} security issue(s)."
        )

        return CodebaseHealth(
            overall_score=overall_score,
            overall_grade=overall_grade,
            architecture_health=arch_sub,
            security_posture=sec_sub,
            total_deductions_count=total_deductions,
            summary=summary,
        )
