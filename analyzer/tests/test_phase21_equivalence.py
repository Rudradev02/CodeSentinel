"""Unit tests for Phase 21 finding reconciliation and equivalence checker."""

from analyzer.incremental.equivalence import EquivalenceChecker
from analyzer.incremental.models import FindingReconciliationState
from analyzer.incremental.reconciliation import FindingReconciler
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisStatus,
    ArchitectureSummary,
    CodebaseHealth,
    RepositoryInfo,
    SecuritySummary,
)


def _make_finding(id_str: str, rule_id: str, file_path: str, line: int, snippet: str = "x = 1") -> Finding:
    return Finding(
        id=id_str,
        rule_id=rule_id,
        rule_name=rule_id,
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path=file_path, line_start=line),
        code_snippet=snippet,
        description="test defect",
        remediation="fix defect",
    )


def _make_result(findings: list[Finding]) -> AnalysisResult:
    return AnalysisResult(
        repository=RepositoryInfo(name="repo", local_path="/tmp/repo"),
        status=AnalysisStatus.COMPLETED,
        metadata=AnalysisMetadata(),
        security_summary=SecuritySummary(total=len(findings)),
        architecture_summary=ArchitectureSummary(total_modules=5),
        security_findings=findings,
        architecture_findings=[],
        health=CodebaseHealth(overall_score=85.0, overall_grade="B"),
    )


class TestFindingReconciliation:
    """Verifies reconciliation of findings across reusable, recomputed, new, and deleted states."""

    def test_reconciliation_states(self):
        f1 = _make_finding("f1", "SEC-001", "unaffected.py", 10)
        f2 = _make_finding("f2", "SEC-002", "modified.py", 20)
        f3 = _make_finding("f3", "SEC-003", "deleted.py", 30)

        prev_findings = [f1, f2, f3]

        # Freshly computed findings for modified.py
        f2_recomputed = _make_finding("f2", "SEC-002", "modified.py", 20)
        f4_new = _make_finding("f4", "SEC-004", "modified.py", 25)
        new_findings = [f2_recomputed, f4_new]

        reconciled, counts = FindingReconciler.reconcile(
            previous_findings=prev_findings,
            newly_computed_findings=new_findings,
            affected_files={"modified.py"},
            deleted_files={"deleted.py"},
        )

        reconciled_ids = {f.id for f in reconciled}
        assert reconciled_ids == {"f1", "f2", "f4"}
        assert "f3" not in reconciled_ids  # f3 was resolved by file deletion

        assert counts[FindingReconciliationState.REUSED.value] == 1
        assert counts[FindingReconciliationState.RECOMPUTED.value] == 1
        assert counts[FindingReconciliationState.NEW.value] == 1
        assert counts[FindingReconciliationState.RESOLVED.value] == 1


class TestEquivalenceChecker:
    """Verifies detection of equivalence, missing findings, phantom findings, and line relocations."""

    def test_exact_equivalence(self):
        f1 = _make_finding("f1", "SEC-001", "main.py", 10, "eval(x)")
        res_full = _make_result([f1])
        res_inc = _make_result([f1])

        eq = EquivalenceChecker.compare(res_full, res_inc)
        assert eq.is_equivalent is True
        assert eq.missing_findings_count == 0
        assert eq.phantom_findings_count == 0

    def test_missing_and_phantom_detection(self):
        f1 = _make_finding("f1", "SEC-001", "a.py", 10, "sql(x)")
        f2 = _make_finding("f2", "SEC-002", "b.py", 20, "exec(y)")

        res_full = _make_result([f1])
        res_inc = _make_result([f2])

        eq = EquivalenceChecker.compare(res_full, res_inc)
        assert eq.is_equivalent is False
        assert eq.missing_findings_count == 1
        assert eq.phantom_findings_count == 1

    def test_relocated_finding_matching(self):
        # f_old at line 10, f_new at line 15 with same rule, path, snippet
        f_old = _make_finding("f_old", "SEC-001", "main.py", 10, "eval(x)")
        f_shifted = _make_finding("f_new", "SEC-001", "main.py", 15, "eval(x)")

        res_full = _make_result([f_old])
        res_inc = _make_result([f_shifted])

        eq = EquivalenceChecker.compare(res_full, res_inc)
        assert eq.relocated_findings_count == 1
        assert eq.missing_findings_count == 0
        assert eq.phantom_findings_count == 0
        assert eq.is_equivalent is True
