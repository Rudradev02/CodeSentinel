"""Test suite for Phase 27: Compliance Assurance & Standards Validation."""

from datetime import datetime, timedelta, timezone
import pytest

from analyzer.compliance.catalogs import ALL_COMPLIANCE_CONTROLS, find_control_by_id
from analyzer.compliance.evaluator import ComplianceEvaluator
from analyzer.compliance.models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceStatus,
    ControlProvenance,
    MappingType,
)
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)


def _make_test_finding(
    rule_id: str,
    finding_id: str = "find-1",
    suppression_expires_at: str | None = None,
    proof_obligations: list[dict] | None = None,
) -> Finding:
    ev = {}
    if suppression_expires_at:
        ev["suppression_expires_at"] = suppression_expires_at
        ev["suppressed"] = True
    if proof_obligations is not None:
        ev["proof_obligations"] = proof_obligations

    return Finding(
        id=finding_id,
        rule_id=rule_id,
        rule_name="Test Rule",
        description="Test Finding Description",
        remediation="Test remediation advice",
        code_snippet="password = 'raw_password'",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        location=SourceLocation(file_path="src/main.py", line_start=10, line_end=12),
        evidence=ev if ev else None,
    )


def test_compliance_status_proven_and_aliases():
    """Verify ComplianceStatus semantic states and backward-compatible aliases."""
    # Proven / Violated / Unknown / Not Assessed
    assert ComplianceStatus.PROVEN.value == "PROVEN"
    assert ComplianceStatus.VIOLATED.value == "VIOLATED"
    assert ComplianceStatus.UNKNOWN.value == "UNKNOWN"
    assert ComplianceStatus.NOT_ASSESSED.value == "NOT_ASSESSED"

    # Backward compatibility
    assert ComplianceStatus.COMPLIANT.value == "COMPLIANT"
    assert ComplianceStatus.NON_COMPLIANT.value == "NON_COMPLIANT"

    # Properties
    assert ComplianceStatus.PROVEN.is_passing is True
    assert ComplianceStatus.COMPLIANT.is_passing is True
    assert ComplianceStatus.VIOLATED.is_passing is False
    assert ComplianceStatus.UNKNOWN.is_passing is False
    assert ComplianceStatus.NOT_ASSESSED.is_passing is False

    assert ComplianceStatus.PROVEN.is_failing is False
    assert ComplianceStatus.VIOLATED.is_failing is True
    assert ComplianceStatus.NON_COMPLIANT.is_failing is True


def test_catalogs_have_provenance_and_mapping_type():
    """Verify that all controls in catalogs have Phase 27 provenance, mapping_type, and static_limitations."""
    for fw, controls in ALL_COMPLIANCE_CONTROLS.items():
        assert len(controls) > 0
        for ctrl in controls:
            assert isinstance(ctrl.mapping_type, MappingType)
            assert ctrl.mapping_type in (
                MappingType.DIRECT,
                MappingType.SUPPORTING,
                MappingType.PARTIAL,
                MappingType.INFERRED,
                MappingType.NOT_ASSESSABLE,
            )
            assert isinstance(ctrl.static_limitations, list)
            assert len(ctrl.static_limitations) > 0
            assert isinstance(ctrl.provenance, ControlProvenance)
            assert ctrl.provenance.source_standard != ""
            assert ctrl.framework_version != ""


def test_evaluator_require_proven_mode():
    """Verify that require_proven=True marks unproven controls as UNKNOWN rather than PROVEN."""
    evaluator_standard = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0], require_proven=False)
    evaluator_proven = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0], require_proven=True)

    # Clean codebase (no findings)
    res_standard = evaluator_standard.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [])
    res_proven = evaluator_proven.evaluate_framework(ComplianceFramework.PCI_DSS_V4_0, [])

    # In standard mode, controls without findings are PROVEN (COMPLIANT)
    assert res_standard.proven_controls > 0
    assert res_standard.unknown_controls == 0

    # In require_proven mode, controls without proof obligations cannot be proven by absence of findings
    assert res_proven.unknown_controls > 0
    assert res_proven.proven_controls == 0


def test_evaluator_require_proven_with_verified_proof_obligations():
    """Verify that require_proven=True marks controls as PROVEN when proof obligations are VERIFIED."""
    evaluator_proven = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0], require_proven=True)

    # Finding with verified proof obligations
    pci_ctrl = find_control_by_id("PCI-6.2.4")
    assert pci_ctrl is not None
    target_rule = pci_ctrl.mapped_rule_ids[0]

    verified_finding = _make_test_finding(
        rule_id=target_rule,
        proof_obligations=[
            {"obligation_id": "OBL-1", "state": "PROVEN_SAFE"},
            {"obligation_id": "OBL-2", "state": "PROVEN_SAFE"},
        ],
    )

    eval_result = evaluator_proven.evaluate_control(pci_ctrl, [verified_finding])
    assert eval_result.status == ComplianceStatus.PROVEN
    assert eval_result.proven_obligations_count == 2
    assert eval_result.violated_obligations_count == 0


def test_timed_suppression_expiration():
    """Verify that expired suppressions revert to active findings during compliance assessment."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0], require_proven=True)
    pci_ctrl = find_control_by_id("PCI-6.2.4")
    assert pci_ctrl is not None
    target_rule = pci_ctrl.mapped_rule_ids[0]

    # Past expiration date -> expired, should be active
    past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    finding_expired = _make_test_finding(
        rule_id=target_rule,
        suppression_expires_at=past_time,
    )

    res_expired = evaluator.evaluate_control(pci_ctrl, [finding_expired])
    assert res_expired.status == ComplianceStatus.VIOLATED
    assert res_expired.status.is_failing is True
    assert res_expired.active_violation_count == 1
    assert res_expired.suppressed_violation_count == 0

    # Future expiration date -> still suppressed
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    finding_valid_suppression = _make_test_finding(
        rule_id=target_rule,
        suppression_expires_at=future_time,
    )

    res_valid = evaluator.evaluate_control(pci_ctrl, [finding_valid_suppression])
    assert res_valid.status == ComplianceStatus.PARTIAL
    assert res_valid.active_violation_count == 0
    assert res_valid.suppressed_violation_count == 1
