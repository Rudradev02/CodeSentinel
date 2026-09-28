"""Tests for RulePack data model and configuration parsing."""

import pytest
from analyzer.compliance.models import ComplianceFramework
from analyzer.models.findings import FindingSeverity
from analyzer.rules.rule_pack import RuleOverride, RulePack


def test_rule_override_model():
    """Verify RuleOverride field validation and immutability."""
    ro = RuleOverride(rule_id="SEC-PY-001", enabled=True, severity_override=FindingSeverity.CRITICAL)
    assert ro.rule_id == "SEC-PY-001"
    assert ro.enabled is True
    assert ro.severity_override == FindingSeverity.CRITICAL

    with pytest.raises(Exception):
        ro.enabled = False


def test_rule_pack_model_defaults():
    """Verify RulePack defaults and constraints."""
    rp = RulePack(
        pack_id="fintech-core",
        name="Fintech Core Pack",
        compliance_frameworks=[ComplianceFramework.PCI_DSS_V4_0],
    )
    assert rp.pack_id == "fintech-core"
    assert rp.version == "1.0.0"
    assert rp.allow_repo_override is True
    assert rp.disallow_inline_suppressions is False
    assert len(rp.rule_overrides) == 0


def test_rule_pack_with_overrides():
    """Verify RulePack correctly validates embedded rule overrides."""
    rp = RulePack(
        pack_id="strict-crypto",
        name="Strict Cryptography",
        rule_overrides=[
            RuleOverride(rule_id="SEC-PY-006", enabled=True, severity_override=FindingSeverity.CRITICAL),
            RuleOverride(rule_id="SEC-JS-005", enabled=True, severity_override=FindingSeverity.CRITICAL),
        ],
        disallow_inline_suppressions=True,
    )
    assert len(rp.rule_overrides) == 2
    assert rp.disallow_inline_suppressions is True


def test_rule_pack_json_roundtrip():
    """Verify serialization and deserialization of RulePack."""
    rp = RulePack(
        pack_id="pci-pack",
        name="PCI Pack",
        extends=["org-baseline"],
        compliance_frameworks=[ComplianceFramework.PCI_DSS_V4_0],
    )
    raw_json = rp.model_dump_json()
    reconstituted = RulePack.model_validate_json(raw_json)
    assert reconstituted.pack_id == rp.pack_id
    assert reconstituted.extends == ["org-baseline"]
