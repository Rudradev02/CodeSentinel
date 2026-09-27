"""Policy-aware finding reconciliation engine for CodeSentinel (Phase 25).

When security policies change between analysis runs, this module classifies
transitions as POLICY_INDUCED rather than plain NEW/RESOLVED, reducing noise
in differential reports and CI gates.
"""

from __future__ import annotations

from typing import Any, Optional

from analyzer.rules.policy import SecurityPolicy, PolicyEnforcementMode


class PolicyDiff:
    """Computed difference between two sets of security policies."""

    def __init__(
        self,
        added_policy_ids: Optional[set[str]] = None,
        removed_policy_ids: Optional[set[str]] = None,
        changed_policy_ids: Optional[set[str]] = None,
        enforcement_changes: Optional[dict[str, tuple[str, str]]] = None,
    ):
        self.added_policy_ids: set[str] = added_policy_ids or set()
        self.removed_policy_ids: set[str] = removed_policy_ids or set()
        self.changed_policy_ids: set[str] = changed_policy_ids or set()
        # Maps policy_id -> (old_enforcement, new_enforcement)
        self.enforcement_changes: dict[str, tuple[str, str]] = enforcement_changes or {}

    @property
    def has_changes(self) -> bool:
        """Whether any policy differences exist."""
        return bool(
            self.added_policy_ids
            or self.removed_policy_ids
            or self.changed_policy_ids
            or self.enforcement_changes
        )

    def is_policy_added_or_tightened(self, policy_id: str) -> bool:
        """Check if a policy was added or had its requirements tightened."""
        if policy_id in self.added_policy_ids:
            return True
        if policy_id in self.changed_policy_ids:
            return True
        if policy_id in self.enforcement_changes:
            old, new = self.enforcement_changes[policy_id]
            # ADVISORY -> ENFORCE is a tightening
            if old == PolicyEnforcementMode.ADVISORY.value and new == PolicyEnforcementMode.ENFORCE.value:
                return True
            # DISABLED -> ENFORCE or ADVISORY is a tightening
            if old == PolicyEnforcementMode.DISABLED.value and new != PolicyEnforcementMode.DISABLED.value:
                return True
        return False

    def is_policy_removed_or_relaxed(self, policy_id: str) -> bool:
        """Check if a policy was removed or had its requirements relaxed."""
        if policy_id in self.removed_policy_ids:
            return True
        if policy_id in self.enforcement_changes:
            old, new = self.enforcement_changes[policy_id]
            # ENFORCE -> ADVISORY or DISABLED is relaxation
            if old == PolicyEnforcementMode.ENFORCE.value and new != PolicyEnforcementMode.ENFORCE.value:
                return True
            # ADVISORY -> DISABLED is relaxation
            if old == PolicyEnforcementMode.ADVISORY.value and new == PolicyEnforcementMode.DISABLED.value:
                return True
        return False


def compute_policy_diff(
    baseline_policies: list[SecurityPolicy],
    current_policies: list[SecurityPolicy],
) -> PolicyDiff:
    """Compute the structural difference between two sets of security policies.

    Identifies added, removed, and changed policies including enforcement
    mode transitions and requirement changes.

    Args:
        baseline_policies: Security policies from the baseline run.
        current_policies: Security policies from the current run.

    Returns:
        A PolicyDiff describing all changes.
    """
    baseline_map = {p.policy_id: p for p in baseline_policies}
    current_map = {p.policy_id: p for p in current_policies}

    baseline_ids = set(baseline_map.keys())
    current_ids = set(current_map.keys())

    added = current_ids - baseline_ids
    removed = baseline_ids - current_ids
    common = baseline_ids & current_ids

    changed: set[str] = set()
    enforcement_changes: dict[str, tuple[str, str]] = {}

    for pid in common:
        bp = baseline_map[pid]
        cp = current_map[pid]

        # Check enforcement mode change
        if bp.enforcement_mode != cp.enforcement_mode:
            enforcement_changes[pid] = (bp.enforcement_mode.value, cp.enforcement_mode.value)

        # Check version or requirements change
        if bp.version != cp.version:
            changed.add(pid)
        elif bp.required_security_properties != cp.required_security_properties:
            changed.add(pid)
        elif bp.require_authentication != cp.require_authentication:
            changed.add(pid)
        elif bp.require_authorization != cp.require_authorization:
            changed.add(pid)
        elif bp.target_sink_categories != cp.target_sink_categories:
            changed.add(pid)
        elif bp.source_boundaries != cp.source_boundaries:
            changed.add(pid)
        elif bp.allowed_sanitizers != cp.allowed_sanitizers:
            changed.add(pid)

    return PolicyDiff(
        added_policy_ids=added,
        removed_policy_ids=removed,
        changed_policy_ids=changed,
        enforcement_changes=enforcement_changes,
    )


def classify_policy_induced_transition(
    finding: Any,
    policy_diff: PolicyDiff,
    is_new: bool = True,
) -> Optional[str]:
    """Determine if a finding transition is policy-induced.

    Args:
        finding: A Finding model instance.
        policy_diff: The computed policy diff between runs.
        is_new: Whether the finding is NEW (vs RESOLVED).

    Returns:
        ``"POLICY_INDUCED_NEW"`` or ``"POLICY_INDUCED_RESOLVED"`` if the
        transition is policy-induced, else ``None``.
    """
    if not policy_diff.has_changes:
        return None

    # Try to determine associated policy ID from finding evidence
    evidence = getattr(finding, "evidence", {}) or {}
    policy_id = evidence.get("policy_id")

    if is_new:
        # Check if any added/tightened policy could explain this new finding
        if policy_id and policy_diff.is_policy_added_or_tightened(policy_id):
            return "POLICY_INDUCED_NEW"
        # Check enforcement upgrades
        for pid, (old_mode, new_mode) in policy_diff.enforcement_changes.items():
            if old_mode in ("DISABLED", "ADVISORY") and new_mode == "ENFORCE":
                return "POLICY_INDUCED_NEW"
        if policy_diff.added_policy_ids or policy_diff.changed_policy_ids:
            return "POLICY_INDUCED_NEW"
    else:
        # Resolved finding
        if policy_id and policy_diff.is_policy_removed_or_relaxed(policy_id):
            return "POLICY_INDUCED_RESOLVED"
        for pid, (old_mode, new_mode) in policy_diff.enforcement_changes.items():
            if old_mode == "ENFORCE" and new_mode in ("DISABLED", "ADVISORY"):
                return "POLICY_INDUCED_RESOLVED"
        if policy_diff.removed_policy_ids or policy_diff.changed_policy_ids:
            return "POLICY_INDUCED_RESOLVED"

    return None
