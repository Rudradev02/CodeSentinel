"""Hierarchical rule pack resolver, DAG validator, and monotonic strictness engine (Phase 26)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional
import yaml

from analyzer.compliance.models import ComplianceFramework
from analyzer.models.findings import FindingSeverity
from analyzer.rules.policy import SecurityPolicy
from analyzer.rules.rule_pack import RuleOverride, RulePack

SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.HIGH: 4,
    FindingSeverity.CRITICAL: 5,
}


class CircularPackDependencyError(Exception):
    """Raised when rule pack inheritance contains a circular cycle."""
    pass


class MonotonicPolicyViolationError(Exception):
    """Raised when child configuration attempts to relax a locked parent enterprise rule."""
    pass


class ResolvedRulePackConfig:
    """Consolidated configuration resulting from hierarchical rule pack composition."""

    def __init__(
        self,
        active_packs: list[RulePack],
        rule_overrides: dict[str, RuleOverride],
        policies: list[SecurityPolicy],
        compliance_frameworks: set[ComplianceFramework],
        disallow_inline_suppressions: bool,
        gate_policy: Optional[dict[str, Any]] = None,
    ):
        self.active_packs = active_packs
        self.rule_overrides = rule_overrides
        self.policies = policies
        self.compliance_frameworks = compliance_frameworks
        self.disallow_inline_suppressions = disallow_inline_suppressions
        self.gate_policy = gate_policy


class RulePackResolver:
    """Manages and resolves hierarchical rule pack inheritance trees."""

    def __init__(self, pack_directories: Optional[list[Path]] = None):
        self._packs: dict[str, RulePack] = {}
        self._pack_dirs = pack_directories or []
        self._load_builtin_packs()

    def register_pack(self, pack: RulePack) -> None:
        """Register an in-memory RulePack instance."""
        self._packs[pack.pack_id] = pack

    def get_pack(self, pack_id: str) -> Optional[RulePack]:
        """Retrieve a registered RulePack by identifier."""
        return self._packs.get(pack_id)

    def load_pack_from_yaml(self, yaml_content: str) -> RulePack:
        """Parse and register a RulePack from YAML string."""
        raw = yaml.safe_load(yaml_content)
        pack = RulePack.model_validate(raw)
        self.register_pack(pack)
        return pack

    def load_pack_file(self, file_path: str | Path) -> RulePack:
        """Load and register a RulePack from a file path."""
        p = Path(file_path)
        with open(p, "r", encoding="utf-8") as f:
            pack = self.load_pack_from_yaml(f.read())
        return pack

    def _load_builtin_packs(self) -> None:
        """Load built-in curated rule packs if available."""
        builtin_dir = Path(__file__).parent / "packs"
        if builtin_dir.is_dir():
            for yaml_file in builtin_dir.glob("*.yaml"):
                try:
                    self.load_pack_file(yaml_file)
                except Exception:
                    pass

    def _resolve_pack_dependencies(self, pack_id: str, visited: set[str], path: list[str]) -> list[str]:
        """Traverse pack dependencies and detect circular loops via DFS."""
        if pack_id in path:
            cycle = path[path.index(pack_id):] + [pack_id]
            raise CircularPackDependencyError(f"Circular pack dependency detected: {' -> '.join(cycle)}")

        pack = self._packs.get(pack_id)
        if not pack:
            # Check if pack_id is a file path
            pack_path = Path(pack_id)
            if pack_path.exists() and pack_path.is_file():
                pack = self.load_pack_file(pack_path)
            else:
                raise ValueError(f"Referenced rule pack not found: '{pack_id}'")

        ordered: list[str] = []
        new_path = path + [pack_id]

        for parent_id in pack.extends:
            if parent_id not in visited:
                parent_ordered = self._resolve_pack_dependencies(parent_id, visited, new_path)
                for pid in parent_ordered:
                    if pid not in ordered:
                        ordered.append(pid)

        if pack_id not in ordered:
            ordered.append(pack_id)
        visited.add(pack_id)
        return ordered

    def resolve_packs(
        self,
        requested_pack_ids: list[str],
        repo_overrides: Optional[list[RuleOverride]] = None,
    ) -> ResolvedRulePackConfig:
        """Resolve a list of requested rule packs with inheritance and monotonic checking."""
        all_ordered_ids: list[str] = []
        visited: set[str] = set()

        for req_id in requested_pack_ids:
            ordered = self._resolve_pack_dependencies(req_id, visited, [])
            for pid in ordered:
                if pid not in all_ordered_ids:
                    all_ordered_ids.append(pid)

        resolved_packs = [self._packs[pid] for pid in all_ordered_ids]

        # Monotonic locking tracking: rule_id -> (locked_enabled, locked_min_severity, locked_by_pack)
        locked_rules: dict[str, tuple[bool, Optional[FindingSeverity], str]] = {}

        merged_overrides: dict[str, RuleOverride] = {}
        merged_policies: dict[str, SecurityPolicy] = {}
        merged_frameworks: set[ComplianceFramework] = set()
        disallow_inline = False
        gate_policy: Optional[dict[str, Any]] = None

        for pack in resolved_packs:
            if pack.disallow_inline_suppressions:
                disallow_inline = True
            if pack.gate_policy:
                gate_policy = dict(pack.gate_policy)

            for fw in pack.compliance_frameworks:
                merged_frameworks.add(fw)

            for pol in pack.policies:
                merged_policies[pol.policy_id] = pol

            for ro in pack.rule_overrides:
                # Check monotonic constraints from previous locked packs
                if ro.rule_id in locked_rules:
                    locked_enabled, locked_min_sev, locked_by = locked_rules[ro.rule_id]
                    if locked_enabled and ro.enabled is False:
                        raise MonotonicPolicyViolationError(
                            f"Rule '{ro.rule_id}' cannot be disabled in pack '{pack.pack_id}'; "
                            f"it is locked by enterprise pack '{locked_by}'"
                        )
                    if locked_min_sev and ro.severity_override:
                        if SEVERITY_ORDER[ro.severity_override] < SEVERITY_ORDER[locked_min_sev]:
                            raise MonotonicPolicyViolationError(
                                f"Rule '{ro.rule_id}' severity cannot be demoted to {ro.severity_override} "
                                f"in pack '{pack.pack_id}'; locked to minimum {locked_min_sev} by '{locked_by}'"
                            )

                merged_overrides[ro.rule_id] = ro

                # If this pack locks rules against child relaxation
                if not pack.allow_repo_override:
                    curr_enabled = ro.enabled if ro.enabled is not None else True
                    locked_rules[ro.rule_id] = (curr_enabled, ro.severity_override, pack.pack_id)

        # Apply repo-level overrides with monotonic verification
        if repo_overrides:
            for ro in repo_overrides:
                if ro.rule_id in locked_rules:
                    locked_enabled, locked_min_sev, locked_by = locked_rules[ro.rule_id]
                    if locked_enabled and ro.enabled is False:
                        raise MonotonicPolicyViolationError(
                            f"Repository configuration cannot disable rule '{ro.rule_id}'; "
                            f"it is locked by enterprise pack '{locked_by}'"
                        )
                    if locked_min_sev and ro.severity_override:
                        if SEVERITY_ORDER[ro.severity_override] < SEVERITY_ORDER[locked_min_sev]:
                            raise MonotonicPolicyViolationError(
                                f"Repository configuration cannot demote rule '{ro.rule_id}' to "
                                f"{ro.severity_override}; locked to minimum {locked_min_sev} by '{locked_by}'"
                            )
                merged_overrides[ro.rule_id] = ro

        return ResolvedRulePackConfig(
            active_packs=resolved_packs,
            rule_overrides=merged_overrides,
            policies=list(merged_policies.values()),
            compliance_frameworks=merged_frameworks,
            disallow_inline_suppressions=disallow_inline,
            gate_policy=gate_policy,
        )
