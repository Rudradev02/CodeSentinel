"""Test suite for Phase 27: Rule Pack Monotonicity & Canonical Hashing."""

import pytest

from analyzer.models.findings import FindingSeverity
from analyzer.rules.pack_resolver import (
    MonotonicPolicyViolationError,
    RulePackResolver,
    compute_canonical_pack_hash,
)
from analyzer.rules.rule_pack import RuleOverride, RulePack


def test_resolved_pack_hash_determinism():
    """Verify that resolved_pack_hash is deterministic and changes upon configuration changes."""
    resolver = RulePackResolver()
    resolved_1 = resolver.resolve_packs(["pci-dss-v4"])
    resolved_2 = resolver.resolve_packs(["pci-dss-v4"])

    assert resolved_1.resolved_pack_hash != ""
    assert resolved_1.resolved_pack_hash == resolved_2.resolved_pack_hash

    # Different pack -> different hash
    resolved_soc2 = resolver.resolve_packs(["soc2-cloud"])
    assert resolved_soc2.resolved_pack_hash != resolved_1.resolved_pack_hash


def test_parameter_monotonicity_decrease_below_locked_parent_rejected():
    """Verify that a child pack cannot decrease parameter below locked parent minimum."""
    resolver = RulePackResolver()

    # Parent locks SEC-PY-001 max_taint_depth=20
    parent = RulePack(
        pack_id="parent-pack-1",
        version="1.0.0",
        name="Parent",
        description="Parent pack",
        allow_repo_override=False,
        rule_overrides=[
            RuleOverride(
                rule_id="SEC-PY-001",
                parameter_overrides={"max_taint_depth": 20},
            )
        ],
    )
    resolver.register_pack(parent)

    # Child attempts to decrease max_taint_depth to 10
    child = RulePack(
        pack_id="child-loosened-taint",
        version="1.0.0",
        name="Child",
        description="Child pack",
        extends=["parent-pack-1"],
        rule_overrides=[
            RuleOverride(
                rule_id="SEC-PY-001",
                parameter_overrides={"max_taint_depth": 10},
            )
        ],
    )
    resolver.register_pack(child)

    with pytest.raises(MonotonicPolicyViolationError, match="max_taint_depth.*cannot be decreased"):
        resolver.resolve_packs(["child-loosened-taint"])


def test_parameter_monotonicity_increase_or_equality_accepted():
    """Verify that a child pack maintaining or increasing parameter above parent is accepted."""
    resolver = RulePackResolver()

    parent = RulePack(
        pack_id="parent-pack-2",
        version="1.0.0",
        name="Parent 2",
        description="Parent pack",
        allow_repo_override=False,
        rule_overrides=[
            RuleOverride(
                rule_id="SEC-PY-001",
                parameter_overrides={"max_taint_depth": 20},
            )
        ],
    )
    resolver.register_pack(parent)

    # Child sets max_taint_depth to 25 (>= 20)
    child = RulePack(
        pack_id="child-tightened",
        version="1.0.0",
        name="Child Tightened",
        description="Child pack",
        extends=["parent-pack-2"],
        rule_overrides=[
            RuleOverride(
                rule_id="SEC-PY-001",
                parameter_overrides={"max_taint_depth": 25},
            )
        ],
    )
    resolver.register_pack(child)

    resolved = resolver.resolve_packs(["child-tightened"])
    assert resolved.rule_overrides["SEC-PY-001"].parameter_overrides["max_taint_depth"] == 25


def test_gate_policy_monotonicity_loosening_rejected():
    """Verify that a child pack cannot loosen fail_on severity gate below locked parent."""
    resolver = RulePackResolver()

    parent = RulePack(
        pack_id="parent-gate-pack",
        version="1.0.0",
        name="Parent Gate",
        description="Parent with HIGH fail_on",
        allow_repo_override=False,
        gate_policy={"fail_on": "HIGH"},
    )
    resolver.register_pack(parent)

    # Child attempts to loosen fail_on to CRITICAL (fewer things fail)
    child = RulePack(
        pack_id="child-loosened-gate",
        version="1.0.0",
        name="Child Loosened Gate",
        description="Child loosening gate",
        extends=["parent-gate-pack"],
        gate_policy={"fail_on": "CRITICAL"},
    )
    resolver.register_pack(child)

    with pytest.raises(MonotonicPolicyViolationError, match="cannot relax gate policy threshold to CRITICAL"):
        resolver.resolve_packs(["child-loosened-gate"])


def test_gate_policy_monotonicity_tightening_accepted():
    """Verify that a child pack tightening fail_on (e.g. HIGH -> MEDIUM) is accepted."""
    resolver = RulePackResolver()

    parent = RulePack(
        pack_id="parent-gate-pack-2",
        version="1.0.0",
        name="Parent Gate 2",
        description="Parent with HIGH fail_on",
        allow_repo_override=False,
        gate_policy={"fail_on": "HIGH"},
    )
    resolver.register_pack(parent)

    # Child tightens to MEDIUM (more things fail)
    child = RulePack(
        pack_id="child-tightened-gate",
        version="1.0.0",
        name="Child Tightened Gate",
        description="Child tightening gate",
        extends=["parent-gate-pack-2"],
        gate_policy={"fail_on": "MEDIUM"},
    )
    resolver.register_pack(child)

    resolved = resolver.resolve_packs(["child-tightened-gate"])
    assert resolved.gate_policy["fail_on"] == "MEDIUM"
