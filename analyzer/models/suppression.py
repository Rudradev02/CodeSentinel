"""Finding suppression models for CodeSentinel (Phase 25).

Defines structured suppression records that allow developers to acknowledge,
defer, or mark findings as false positives through inline annotations or
repository configuration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class SuppressionKind(str, Enum):
    """Classification of finding suppression mechanism."""
    INLINE_ANNOTATION = "INLINE_ANNOTATION"    # Source code comment: # codesentinel-suppress SEC-PY-005
    CONFIG_EXCLUSION = "CONFIG_EXCLUSION"       # .codesentinel.yaml rule exclusion
    TIMED_DEFERRAL = "TIMED_DEFERRAL"          # Deferred until expiration date
    FALSE_POSITIVE = "FALSE_POSITIVE"          # Marked as confirmed false positive


class SuppressionScope(str, Enum):
    """Granularity of the suppression target."""
    FINDING = "FINDING"            # Specific finding by fingerprint
    RULE = "RULE"                  # All findings from a specific rule ID
    FILE = "FILE"                  # All findings in a specific file
    RULE_IN_FILE = "RULE_IN_FILE"  # Specific rule in a specific file


class FindingSuppression(BaseModel):
    """A developer-specified suppression of one or more findings.

    Suppressions can be scoped to a specific finding (by fingerprint),
    a rule ID, a file path, or a rule-in-file combination.
    """
    model_config = ConfigDict(frozen=True)

    suppression_id: str = Field(..., description="Unique suppression identifier")
    kind: SuppressionKind = Field(..., description="Mechanism by which suppression was declared")
    scope: SuppressionScope = Field(..., description="Granularity of the suppression target")
    target_rule_id: Optional[str] = Field(default=None, description="Rule ID targeted by this suppression")
    target_file_path: Optional[str] = Field(default=None, description="File path targeted by this suppression")
    target_fingerprint: Optional[str] = Field(default=None, description="primary_hash of targeted finding")
    reason: str = Field(default="", description="Developer-provided justification")
    author: Optional[str] = Field(default=None, description="Author of the suppression")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(default=None, description="Expiration for TIMED_DEFERRAL")
    is_active: bool = Field(default=True, description="Whether the suppression is currently active")

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check whether a timed deferral suppression has expired."""
        if self.expires_at is None:
            return False
        reference = now or datetime.now(timezone.utc)
        # Ensure timezone-aware comparison
        if self.expires_at.tzinfo is None:
            return reference.replace(tzinfo=None) > self.expires_at
        return reference > self.expires_at

    def matches_finding(
        self,
        rule_id: str,
        file_path: str,
        primary_hash: Optional[str] = None,
    ) -> bool:
        """Check whether this suppression matches a given finding.

        Args:
            rule_id: The rule ID of the finding.
            file_path: Normalized file path of the finding.
            primary_hash: The primary fingerprint hash of the finding.

        Returns:
            True if the suppression applies to the given finding.
        """
        if not self.is_active:
            return False

        norm_path = file_path.replace("\\", "/").strip("/").lower()
        target_norm = (self.target_file_path or "").replace("\\", "/").strip("/").lower()

        if self.scope == SuppressionScope.FINDING:
            return (
                self.target_fingerprint is not None
                and primary_hash is not None
                and self.target_fingerprint == primary_hash
            )
        elif self.scope == SuppressionScope.RULE:
            return self.target_rule_id == rule_id
        elif self.scope == SuppressionScope.FILE:
            return target_norm == norm_path
        elif self.scope == SuppressionScope.RULE_IN_FILE:
            return self.target_rule_id == rule_id and target_norm == norm_path
        return False
