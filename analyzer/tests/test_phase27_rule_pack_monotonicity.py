"""Test suite for Phase 27: Rule Pack Monotonicity & Canonical Hashing."""

import pytest

from analyzer.rules.models import RulePackDefinition, RulePackOverride
from analyzer.rules.pack_resolver import RulePackResolver, compute_canonical_pack_hash


def test_resolved_pack_hash_determinism():
    """Verify that resolved_pack_hash is deterministic and changes upon configuration changes."""
    resolver = RulePackResolver()
    resolved_1 = resolver.resolve_packs(["security-core"])
    resolved_2 = resolver.resolve_packs(["security-core"])

    assert resolved_1.resolved_pack_hash != ""
    assert resolved_1.resolved_pack_hash == resolved_2.resolved_pack_hash

    # Different pack -> different hash
    resolved_soc2 = resolver.resolve_packs(["soc2-compliance"])
    assert resolved_soc2.resolved_pack_hash != resolved_1.resolved_pack_hash


def test_parameter_monotonicity_taint_depth_loosening_rejected():
    """Verify that a child pack attempting to loosen max_taint_depth is rejected."""
    resolver = RulePackResolver()

    # Parent sets max_taint_depth=20
    parent = RulePackDefinition(
        pack_id="parent-pack-1",
        version="1.0.0",
        name="Parent",
        description="Parent pack",
        analysis_parameters={"max_taint_depth": 20},
    )
    resolver.register_pack(parent)

    # Child attempts to loosen max_taint_depth to 30 (loosening propagation depth)
    child = RulePackDefinition(
        pack_id="child-loosened-taint",
        version="1.0.0",
        name="Child",
        description="Child pack",
        extends="parent-pack-1",
        analysis_parameters={"max_taint_depth": 30},
    )
    resolver.register_pack(child)

    with pytest.raises(ValueError, match="violates parameter monotonicity.*max_taint_depth"):
        resolver.resolve_packs(["child-loosened-taint"])


def test_parameter_monotonicity_tightening_accepted():
    """Verify that a child pack tightening parameters is accepted."""
    resolver = RulePackResolver()

    parent = RulePackDefinition(
        pack_id="parent-pack-2",
        version="1.0.0",
        name="Parent 2",
        description="Parent pack",
        analysis_parameters={"max_taint_depth": 25, "max_call_depth": 5},
    )
    resolver.register_pack(parent)

    # Child tightens taint depth (15 <= 25) and increases call depth (8 >= 5)
    child = RulePackDefinition(
        pack_id="child-tightened",
        version="1.0.0",
        name="Child Tightened",
        description="Child pack",
        extends="parent-pack-2",
        analysis_parameters={"max_taint_depth": 15, "max_call_depth": 8},
    )
    resolver.register_pack(child)

    resolved = resolver.resolve_packs(["child-tightened"])
    assert resolved.analysis_parameters["max_taint_depth"] == 15
    assert resolved.analysis_parameters["max_call_depth"] == 8


def test_gate_policy_monotonicity_loosening_rejected():
    """Verify that a child pack cannot loosen fail_on severity gate."""
    resolver = RulePackResolver()

    parent = RulePackDefinition(
        pack_id="parent-gate-pack",
        version="1.0.0",
        name="Parent Gate",
        description="Parent with HIGH fail_on",
        gate_policies={"fail_on": "HIGH"},
    )
    resolver.register_pack(parent)

    # Child attempts to loosen fail_on to CRITICAL (fewer things fail)
    child = RulePackDefinition(
        pack_id="child-loosened-gate",
        version="1.0.0",
        name="Child Loosened Gate",
        description="Child loosening gate",
        extends="parent-gate-pack",
        gate_policies={"fail_on": "CRITICAL"},
    )
    resolver.register_pack(child)

    with pytest.raises(ValueError, match="violates gate policy monotonicity.*fail_on"):
        resolver.resolve_packs(["child-loosened-gate"])


def test_gate_policy_monotonicity_tightening_accepted():
    """Verify that a child pack tightening fail_on (e.g. HIGH -> MEDIUM) is accepted."""
    resolver = RulePackResolver()

    parent = RulePackDefinition(
        pack_id="parent-gate-pack-2",
        version="1.0.0",
        name="Parent Gate 2",
        description="Parent with HIGH fail_on",
        gate_policies={"fail_on": "HIGH"},
    )
    resolver.register_pack(parent)

    # Child tightens to MEDIUM
    child = RulePackDefinition(
        pack_id="child-tightened-gate",
        version="1.0.0",
        name="Child Tightened Gate",
        description="Child tightening gate",
        extends="parent-gate-pack-2",
        gate_policies={"fail_on": "MEDIUM"},
    )
    resolver.register_pack(child)

    resolved = resolver.resolve_packs(["child-tightened-gate"])
    assert resolved.gate_policies["fail_on"] == "MEDIUM"
