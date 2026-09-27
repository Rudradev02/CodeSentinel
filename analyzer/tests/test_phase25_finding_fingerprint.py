"""Phase 25 tests — Finding fingerprint stability and cross-run matching."""

import pytest

from analyzer.incremental.finding_fingerprint import (
    FindingFingerprint,
    compute_finding_fingerprint,
    compute_fingerprint_for_finding,
    _norm_path_for_fingerprint,
    _norm_snippet_for_fingerprint,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence


def _make_finding(rule_id="SEC-PY-005", file_path="src/db.py", line=10, snippet="cursor.execute(query)"):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path=file_path, line_start=line),
        code_snippet=snippet,
        description="Raw SQL query string construction",
        remediation="Use parameterized queries",
    )


class TestFindingFingerprintStability:
    """Test that fingerprints are deterministic and stable across runs."""

    def test_fingerprint_stable_across_runs(self):
        """Same finding in two separate computations produces identical primary_hash."""
        fp1 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute(query)")
        fp2 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute(query)")
        assert fp1.primary_hash == fp2.primary_hash
        assert fp1.stable_id == fp2.stable_id

    def test_fingerprint_survives_line_shift(self):
        """Moving a finding down 3 lines produces same primary_hash."""
        fp1 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute(query)", line_start=10)
        fp2 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute(query)", line_start=13)
        assert fp1.primary_hash == fp2.primary_hash
        # But location_hash should differ
        assert fp1.location_hash != fp2.location_hash

    def test_fingerprint_changes_on_rule_change(self):
        """Different rule_id produces different primary_hash even with same location."""
        fp1 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute(query)")
        fp2 = compute_finding_fingerprint("SEC-PY-003", "src/db.py", "cursor.execute(query)")
        assert fp1.primary_hash != fp2.primary_hash
        assert fp1.stable_id != fp2.stable_id

    def test_fingerprint_normalization_paths(self):
        """Windows backslash paths and extra whitespace produce same fingerprint."""
        fp1 = compute_finding_fingerprint("SEC-PY-005", "src/db.py", "cursor.execute( query )")
        fp2 = compute_finding_fingerprint("SEC-PY-005", "src\\db.py", "cursor.execute(  query  )")
        assert fp1.primary_hash == fp2.primary_hash

    def test_fingerprint_from_finding_model(self):
        """compute_fingerprint_for_finding extracts correct data from Finding model."""
        finding = _make_finding()
        fp = compute_fingerprint_for_finding(finding)
        assert fp.primary_hash
        assert fp.stable_id.startswith("CS-SEC-PY-005-")
        assert len(fp.primary_hash) == 64  # SHA-256

    def test_composite_hash_with_policy(self):
        """Composite hash incorporates policy context."""
        fp1 = compute_finding_fingerprint(
            "SEC-PY-005", "src/db.py", "cursor.execute(query)",
            policy_id="POL-SQL-01", obligation_kinds=["REQUIRES_PROPERTY"],
        )
        fp2 = compute_finding_fingerprint(
            "SEC-PY-005", "src/db.py", "cursor.execute(query)",
            policy_id="POL-SQL-01", obligation_kinds=["REQUIRES_AUTHENTICATION"],
        )
        assert fp1.composite_hash != fp2.composite_hash
        # Primary hash should still be the same (policy-independent)
        assert fp1.primary_hash == fp2.primary_hash
