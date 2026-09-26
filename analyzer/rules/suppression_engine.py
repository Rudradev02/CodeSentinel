"""Suppression matching engine for CodeSentinel (Phase 25).

Matches active suppression records against emitted findings, tagging
suppressed findings and tracking suppression statistics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from analyzer.incremental.finding_fingerprint import compute_fingerprint_for_finding
from analyzer.models.suppression import FindingSuppression


class SuppressionEngine:
    """Matches suppression records against findings and classifies suppression state.

    Accepts a collection of ``FindingSuppression`` records and evaluates each
    finding to determine if it is suppressed, deferred, or reopened.
    """

    def __init__(self, suppressions: Optional[list[FindingSuppression]] = None):
        self._suppressions: list[FindingSuppression] = list(suppressions or [])

    @property
    def suppression_count(self) -> int:
        """Return the total number of loaded suppressions."""
        return len(self._suppressions)

    def add_suppression(self, suppression: FindingSuppression) -> None:
        """Register an additional suppression."""
        self._suppressions.append(suppression)

    def add_suppressions(self, suppressions: list[FindingSuppression]) -> None:
        """Register multiple additional suppressions."""
        self._suppressions.extend(suppressions)

    def match_finding(
        self,
        finding: object,
        now: Optional[datetime] = None,
    ) -> Optional[FindingSuppression]:
        """Find the first active, non-expired suppression matching a finding.

        Args:
            finding: A Finding model instance with rule_id, location, code_snippet.
            now: Reference time for expiration checks.

        Returns:
            The matching FindingSuppression if found, else None.
        """
        rule_id = getattr(finding, "rule_id", "")
        location = getattr(finding, "location", None)
        file_path = getattr(location, "file_path", "") if location else ""

        # Compute fingerprint for fingerprint-scoped matching
        fingerprint = compute_fingerprint_for_finding(finding)
        primary_hash = fingerprint.primary_hash

        reference_time = now or datetime.now(timezone.utc)

        for suppression in self._suppressions:
            if not suppression.is_active:
                continue
            if suppression.is_expired(reference_time):
                continue
            if suppression.matches_finding(rule_id, file_path, primary_hash):
                return suppression

        return None

    def classify_findings(
        self,
        findings: list[object],
        now: Optional[datetime] = None,
    ) -> tuple[list[object], list[object], list[tuple[object, FindingSuppression]]]:
        """Classify findings into active, suppressed, and deferred categories.

        Args:
            findings: List of Finding model instances.
            now: Reference time for expiration checks.

        Returns:
            Tuple of (active_findings, suppressed_pairs, expired_suppressions)
            where suppressed_pairs is a list of (finding, matching_suppression).
        """
        active: list[object] = []
        suppressed: list[tuple[object, FindingSuppression]] = []
        reopened: list[object] = []

        reference_time = now or datetime.now(timezone.utc)

        for finding in findings:
            match = self.match_finding(finding, reference_time)
            if match is not None:
                suppressed.append((finding, match))
            else:
                active.append(finding)

        return active, reopened, suppressed

    def find_expired_suppressions(
        self,
        now: Optional[datetime] = None,
    ) -> list[FindingSuppression]:
        """Return all suppressions that have expired."""
        reference_time = now or datetime.now(timezone.utc)
        return [s for s in self._suppressions if s.is_expired(reference_time)]

    def get_active_suppressions(
        self,
        now: Optional[datetime] = None,
    ) -> list[FindingSuppression]:
        """Return all currently active (non-expired) suppressions."""
        reference_time = now or datetime.now(timezone.utc)
        return [
            s for s in self._suppressions
            if s.is_active and not s.is_expired(reference_time)
        ]
