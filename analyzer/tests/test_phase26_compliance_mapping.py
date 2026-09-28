"""Tests for Phase 26 compliance models and catalog lookup."""

import pytest
from analyzer.compliance.catalogs import ALL_COMPLIANCE_CONTROLS, find_control_by_id, get_controls_for_framework
from analyzer.compliance.models import ComplianceControl, ComplianceFramework, ComplianceStatus
from analyzer.models.findings import FindingSeverity
from analyzer.models.obligation import ObligationKind


def test_compliance_framework_enum_values():
    """Verify all 4 required regulatory standards are supported."""
    frameworks = {f.value for f in ComplianceFramework}
    assert "PCI_DSS_V4_0" in frameworks
    assert "HIPAA_SECURITY" in frameworks
    assert "SOC2_TSC" in frameworks
    assert "NIST_SP_800_53_R5" in frameworks


def test_compliance_status_enum_values():
    """Verify compliance status lifecycle states and aliases."""
    assert ComplianceStatus.COMPLIANT.value == "COMPLIANT"
    assert ComplianceStatus.NON_COMPLIANT.value == "NON_COMPLIANT"
    assert ComplianceStatus.PARTIALLY_COMPLIANT.value == "PARTIAL"
    assert ComplianceStatus.PARTIAL.value == "PARTIAL"


def test_compliance_control_immutability():
    """Verify ComplianceControl is frozen/immutable."""
    control = ComplianceControl(
        control_id="TEST-01",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        name="Test Control",
        section="Section 1",
        description="Test description",
        criticality=FindingSeverity.HIGH,
    )
    with pytest.raises(Exception):
        control.name = "Mutated"


def test_find_control_by_id():
    """Verify case-insensitive lookup of compliance controls by ID."""
    c1 = find_control_by_id("PCI-6.2.4")
    assert c1 is not None
    assert c1.name == "Software Vulnerability Mitigation"

    c2 = find_control_by_id("hipaa-164.312(a)(1)")
    assert c2 is not None
    assert c2.framework == ComplianceFramework.HIPAA_SECURITY

    c_none = find_control_by_id("NONEXISTENT-CONTROL-99")
    assert c_none is None


def test_all_catalogs_non_empty():
    """Verify each framework has registered controls with valid mappings."""
    for fw in ComplianceFramework:
        controls = get_controls_for_framework(fw)
        assert len(controls) > 0, f"Framework {fw} has no registered controls"
        for c in controls:
            assert c.control_id
            assert c.name
            assert c.section
            assert c.description
            assert isinstance(c.mapped_rule_ids, list)
            assert isinstance(c.mapped_policy_ids, list)
