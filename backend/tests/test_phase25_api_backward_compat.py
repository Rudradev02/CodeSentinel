"""Phase 25 tests — Backend API backward compatibility."""

import pytest

from analyzer.models.comparison import (
    DifferentialFinding,
    FindingTransition,
    FindingLifecycleState,
    ComparisonSummary,
    ComparisonResult,
)
from analyzer.models.findings import (
    Finding,
    SourceLocation,
    FindingCategory,
    EvidenceType,
    FindingSeverity,
    FindingConfidence,
)


def _make_finding():
    return Finding(
        rule_id="SEC-PY-005",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="src/db.py", line_start=10),
        code_snippet="cursor.execute(query)",
        description="SQL injection",
        remediation="Use parameterized queries",
    )


class TestPhase25BackwardCompatibility:
    """Verify that Phase 25 model extensions maintain backward compatibility."""

    def test_finding_serializes_without_fingerprint(self):
        """Finding without fingerprint serializes correctly."""
        f = _make_finding()
        data = f.model_dump()
        assert "fingerprint" in data
        assert data["fingerprint"] is None

    def test_differential_finding_without_lifecycle(self):
        """DifferentialFinding without Phase 25 fields serializes correctly."""
        df = DifferentialFinding(
            finding=_make_finding(),
            transition=FindingTransition.NEW,
        )
        data = df.model_dump()
        assert data["lifecycle_state"] is None
        assert data["regression"] is None
        assert data["suppression"] is None

    def test_comparison_summary_backward_compatible(self):
        """ComparisonSummary with only Phase 9 fields works correctly."""
        summary = ComparisonSummary(
            total_current=10,
            total_baseline=8,
            new_count=3,
            resolved_count=1,
            unchanged_count=4,
            modified_count=2,
        )
        data = summary.model_dump()
        # Phase 25 fields are present with defaults
        assert data["suppressed_count"] == 0
        assert data["regression_count"] == 0
        assert data["gate_verdict"] is None

    def test_comparison_result_serialization_roundtrip(self):
        """ComparisonResult roundtrips through model_dump/model_validate."""
        from datetime import datetime, timezone

        result = ComparisonResult(
            current_id="run-001",
            summary=ComparisonSummary(
                total_current=5,
                total_baseline=3,
                new_count=2,
                resolved_count=0,
                unchanged_count=3,
                regression_count=1,
                gate_verdict="FAIL",
            ),
            findings=[
                DifferentialFinding(
                    finding=_make_finding(),
                    transition=FindingTransition.NEW,
                    lifecycle_state=FindingLifecycleState.REGRESSION,
                ),
            ],
        )
        data = result.model_dump(mode="json")
        restored = ComparisonResult.model_validate(data)
        assert restored.summary.regression_count == 1
        assert restored.findings[0].lifecycle_state == FindingLifecycleState.REGRESSION
