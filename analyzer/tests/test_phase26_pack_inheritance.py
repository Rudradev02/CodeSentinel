"""Tests for hierarchical rule pack inheritance, DAG cycle detection, and monotonic strictness."""

import pytest
from analyzer.compliance.models import ComplianceFramework
from analyzer.models.findings import FindingSeverity
from analyzer.rules.pack_resolver import (
    CircularPackDependencyError,
    MonotonicPolicyViolationError,
    RulePackResolver,
)
from analyzer.rules.rule_pack import RuleOverride, RulePack


def test_single_pack_resolution():
    """Verify single rule pack resolves cleanly."""
    resolver = RulePackResolver()
    pack = RulePack(
        pack_id="pack-a",
        name="Pack A",
        rule_overrides=[RuleOverride(rule_id="SEC-PY-001", enabled=True, severity_override=FindingSeverity.HIGH)],
    )
    resolver.register_pack(pack)
    resolved = resolver.resolve_packs(["pack-a"])

    assert len(resolved.active_packs) == 1
    assert "SEC-PY-001" in resolved.rule_overrides
    assert resolved.rule_overrides["SEC-PY-001"].severity_override == FindingSeverity.HIGH


def test_hierarchical_dag_inheritance():
    """Verify child pack inherits and merges parent pack overrides in topological order."""
    resolver = RulePackResolver()
    base_pack = RulePack(
        pack_id="base",
        name="Base Organization Pack",
        rule_overrides=[RuleOverride(rule_id="SEC-PY-001", enabled=True, severity_override=FindingSeverity.HIGH)],
    )
    child_pack = RulePack(
        pack_id="child",
        name="Child Pack",
        extends=["base"],
        rule_overrides=[RuleOverride(rule_id="SEC-PY-002", enabled=True, severity_override=FindingSeverity.MEDIUM)],
    )
    resolver.register_pack(base_pack)
    resolver.register_pack(child_pack)

    resolved = resolver.resolve_packs(["child"])
    assert len(resolved.active_packs) == 2
    assert resolved.active_packs[0].pack_id == "base"
    assert resolved.active_packs[1].pack_id == "child"
    assert "SEC-PY-001" in resolved.rule_overrides
    assert "SEC-PY-002" in resolved.rule_overrides


def test_cyclic_pack_dependency_detected():
    """Verify circular inheritance loops raise CircularPackDependencyError."""
    resolver = RulePackResolver()
    pack1 = RulePack(pack_id="loop-1", name="Loop 1", extends=["loop-2"])
    pack2 = RulePack(pack_id="loop-2", name="Loop 2", extends=["loop-1"])
    resolver.register_pack(pack1)
    resolver.register_pack(pack2)

    with pytest.raises(CircularPackDependencyError) as exc_info:
        resolver.resolve_packs(["loop-1"])
    assert "Circular pack dependency detected" in str(exc_info.value)


def test_monotonic_strictness_forbids_disabling_locked_rules():
    """Verify child configuration cannot disable a rule locked by parent pack."""
    resolver = RulePackResolver()
    locked_parent = RulePack(
        pack_id="enterprise-locked",
        name="Enterprise Locked Pack",
        allow_repo_override=False,
        rule_overrides=[RuleOverride(rule_id="SEC-PY-003", enabled=True, severity_override=FindingSeverity.CRITICAL)],
    )
    rogue_child = RulePack(
        pack_id="rogue-child",
        name="Rogue Child Pack",
        extends=["enterprise-locked"],
        rule_overrides=[RuleOverride(rule_id="SEC-PY-003", enabled=False)],
    )
    resolver.register_pack(locked_parent)
    resolver.register_pack(rogue_child)

    with pytest.raises(MonotonicPolicyViolationError) as exc:
        resolver.resolve_packs(["rogue-child"])
    assert "cannot be disabled" in str(exc.value)


def test_monotonic_strictness_forbids_severity_demotion():
    """Verify child configuration cannot demote rule severity locked by parent pack."""
    resolver = RulePackResolver()
    locked_parent = RulePack(
        pack_id="enterprise-locked",
        name="Enterprise Locked Pack",
        allow_repo_override=False,
        rule_overrides=[RuleOverride(rule_id="SEC-PY-001", enabled=True, severity_override=FindingSeverity.CRITICAL)],
    )
    resolver.register_pack(locked_parent)

    repo_demotion = [RuleOverride(rule_id="SEC-PY-001", severity_override=FindingSeverity.LOW)]
    with pytest.raises(MonotonicPolicyViolationError) as exc:
        resolver.resolve_packs(["enterprise-locked"], repo_overrides=repo_demotion)
    assert "cannot demote" in str(exc.value)


def test_monotonic_strictness_permits_tightening():
    """Verify child configuration CAN tighten a locked rule (e.g. HIGH -> CRITICAL)."""
    resolver = RulePackResolver()
    locked_parent = RulePack(
        pack_id="enterprise-locked",
        name="Enterprise Locked Pack",
        allow_repo_override=False,
        rule_overrides=[RuleOverride(rule_id="SEC-PY-005", enabled=True, severity_override=FindingSeverity.HIGH)],
    )
    resolver.register_pack(locked_parent)

    repo_tightening = [RuleOverride(rule_id="SEC-PY-005", severity_override=FindingSeverity.CRITICAL)]
    resolved = resolver.resolve_packs(["enterprise-locked"], repo_overrides=repo_tightening)
    assert resolved.rule_overrides["SEC-PY-005"].severity_override == FindingSeverity.CRITICAL
