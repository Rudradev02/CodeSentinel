"""Phase 5 tests for deterministic deduplication in RuleEngine."""

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.rules.engine import deduplicate_findings


def _make_finding(
    rule_id: str,
    file_path: str,
    line: int,
    col: int,
    evidence: dict,
    snippet: str = "code",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=rule_id,
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path=file_path, line_start=line, col_start=col),
        code_snippet=snippet,
        description="desc",
        remediation="remed",
        evidence=evidence,
    )


def test_deduplication_exact_duplicates_removed():
    f1 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "k1"})
    f2 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "k1"})

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1


def test_deduplication_different_columns_preserved():
    f1 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "k1"})
    f2 = _make_finding("SEC-PY-001", "app.py", 10, 20, {"var": "k1"})

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2


def test_deduplication_different_evidence_preserved_on_same_line():
    f1 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "key_a"})
    f2 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "key_b"})

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2


def test_deduplication_different_rules_preserved():
    f1 = _make_finding("SEC-PY-001", "app.py", 10, 0, {"var": "k"})
    f2 = _make_finding("SEC-PY-002", "app.py", 10, 0, {"var": "k"})

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2


def test_deduplication_preserves_deterministic_ordering():
    f3 = _make_finding("SEC-PY-001", "z.py", 5, 0, {})
    f1 = _make_finding("SEC-PY-001", "a.py", 10, 0, {})
    f2 = _make_finding("SEC-PY-001", "a.py", 2, 0, {})

    deduped = deduplicate_findings([f3, f1, f2])
    order = [(f.location.file_path, f.location.line_start) for f in deduped]
    assert order == [("a.py", 2), ("a.py", 10), ("z.py", 5)]
