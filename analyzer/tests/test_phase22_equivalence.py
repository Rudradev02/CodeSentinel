"""Unit tests for Phase 22 extended EquivalenceChecker."""

from datetime import datetime, timezone
from pathlib import Path

from analyzer.incremental.equivalence import (
    EquivalenceChecker,
    EquivalenceDiscrepancyKind,
)
from analyzer.models.findings import (
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
    SubScore,
)


def _make_dummy_result(
    findings: list[Finding] = None,
    contracts_stat: str = "ok",
    comp_stat: str = "ok",
) -> AnalysisResult:
    sub = SubScore(score=100.0, grade="A")
    return AnalysisResult(
        repository=RepositoryInfo(name="test", local_path=".", total_files=1, total_loc=10),
        metadata=AnalysisMetadata(),
        status=AnalysisStatus.COMPLETED,
        security_findings=findings or [],
        architecture_findings=[],
        security_summary=SecuritySummary(),
        architecture_summary=ArchitectureSummary(total_modules=1),
        health=CodebaseHealth(
            overall_score=100.0,
            overall_grade="A",
            architecture_health=sub,
            security_posture=sub,
        ),
        call_graph_summary={
            "contracts": {"status": contracts_stat},
            "composition": {"status": comp_stat},
        },
    )


def test_equivalence_discrepancy_enum():
    """Verify Phase 22 discrepancy kinds are defined in EquivalenceDiscrepancyKind."""
    assert EquivalenceDiscrepancyKind.CONTRACT_MISMATCH.value == "CONTRACT_MISMATCH"
    assert EquivalenceDiscrepancyKind.COMPOSITION_MISMATCH.value == "COMPOSITION_MISMATCH"


def test_equivalence_checker_backward_compatibility():
    """Verify EquivalenceChecker.compare works with default arguments (Phase 21 behavior)."""
    r1 = _make_dummy_result()
    r2 = _make_dummy_result()

    res = EquivalenceChecker.compare(r1, r2)
    assert res.is_equivalent is True
    assert len(res.discrepancies) == 0


def test_equivalence_checker_contracts_verification_match():
    """Verify verify_contracts=True passes when contract summaries match."""
    r1 = _make_dummy_result(contracts_stat="verified")
    r2 = _make_dummy_result(contracts_stat="verified")

    res = EquivalenceChecker.compare(r1, r2, verify_contracts=True)
    assert res.is_equivalent is True
    assert res.contracts_matched is True


def test_equivalence_checker_contracts_verification_mismatch():
    """Verify verify_contracts=True reports discrepancy when contract summaries differ."""
    r1 = _make_dummy_result(contracts_stat="verified_v1")
    r2 = _make_dummy_result(contracts_stat="verified_v2")

    res = EquivalenceChecker.compare(r1, r2, verify_contracts=True)
    assert res.is_equivalent is False
    assert res.contracts_matched is False
    assert any("CONTRACT_MISMATCH" in d for d in res.discrepancies)


def test_equivalence_checker_composition_verification_match():
    """Verify verify_composition=True passes when composition summaries match."""
    r1 = _make_dummy_result(comp_stat="composed")
    r2 = _make_dummy_result(comp_stat="composed")

    res = EquivalenceChecker.compare(r1, r2, verify_composition=True)
    assert res.is_equivalent is True
    assert res.composition_matched is True


def test_equivalence_checker_composition_verification_mismatch():
    """Verify verify_composition=True reports discrepancy when composition summaries differ."""
    r1 = _make_dummy_result(comp_stat="composed_v1")
    r2 = _make_dummy_result(comp_stat="composed_v2")

    res = EquivalenceChecker.compare(r1, r2, verify_composition=True)
    assert res.is_equivalent is False
    assert res.composition_matched is False
    assert any("COMPOSITION_MISMATCH" in d for d in res.discrepancies)
