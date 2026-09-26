"""Security regression classification engine for CodeSentinel (Phase 25).

Classifies newly introduced findings by root cause (code change, policy change,
config change, pre-existing) and urgency (blocking, actionable, advisory).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RegressionCause(str, Enum):
    """Root cause classification for new or changed findings."""
    CODE_CHANGE = "CODE_CHANGE"               # Finding in modified/added source file
    POLICY_CHANGE = "POLICY_CHANGE"           # Finding due to policy addition/tightening
    CONFIG_CHANGE = "CONFIG_CHANGE"           # Finding due to analysis config change
    RULE_CHANGE = "RULE_CHANGE"               # Finding due to new/modified rule
    FRAMEWORK_CHANGE = "FRAMEWORK_CHANGE"     # Finding due to framework model update
    PRE_EXISTING = "PRE_EXISTING"             # Finding in unchanged code, previously undetected
    UNKNOWN = "UNKNOWN"


class RegressionSeverity(str, Enum):
    """Urgency classification for regression findings."""
    BLOCKING = "BLOCKING"           # Must fix before merge (CRITICAL/HIGH in changed code)
    ACTIONABLE = "ACTIONABLE"       # Should fix soon (MEDIUM in changed code)
    ADVISORY = "ADVISORY"           # Informational (LOW/INFO, or policy-induced)
    DEFERRED = "DEFERRED"           # Suppressed or deferred


class RegressionClassification(BaseModel):
    """Rich regression metadata attached to a differential finding."""
    model_config = ConfigDict(frozen=True)

    cause: RegressionCause = Field(..., description="Root cause of the regression")
    severity: RegressionSeverity = Field(..., description="Urgency classification")
    is_in_changed_code: bool = Field(default=False, description="Whether finding is in modified/added code")
    changed_file_path: Optional[str] = Field(default=None, description="The changed file path if applicable")
    policy_id: Optional[str] = Field(default=None, description="Associated policy ID if POLICY_CHANGE")
    config_scope: Optional[str] = Field(default=None, description="Changed config scope if CONFIG_CHANGE")
    explanation: str = Field(default="", description="Human-readable explanation of the classification")


class RegressionClassifier:
    """Classifies new/modified findings by root cause and severity.

    Uses file change information, config fingerprint deltas, and policy
    metadata to determine why a finding appeared and how urgent it is.
    """

    @staticmethod
    def classify(
        finding: Any,
        changed_files: Optional[set[str]] = None,
        affected_files: Optional[set[str]] = None,
        policy_hash_changed: bool = False,
        rules_hash_changed: bool = False,
        cfg_dataflow_hash_changed: bool = False,
        framework_model_hash_changed: bool = False,
        policy_id: Optional[str] = None,
    ) -> RegressionClassification:
        """Classify a new or modified finding.

        Args:
            finding: A Finding model instance.
            changed_files: Set of directly changed file paths (normalized).
            affected_files: Set of transitively affected file paths.
            policy_hash_changed: Whether policy_hash differs from baseline.
            rules_hash_changed: Whether rules_hash differs from baseline.
            cfg_dataflow_hash_changed: Whether cfg_dataflow_hash differs.
            framework_model_hash_changed: Whether framework_model_hash differs.
            policy_id: Optional policy ID associated with the finding.

        Returns:
            A RegressionClassification with cause, severity, and explanation.
        """
        changed = changed_files or set()
        affected = affected_files or set()

        location = getattr(finding, "location", None)
        file_path = getattr(location, "file_path", "") if location else ""
        norm_path = file_path.replace("\\", "/").strip("/").lower()

        finding_severity = getattr(finding, "severity", None)
        sev_value = finding_severity.value if hasattr(finding_severity, "value") else str(finding_severity or "")

        # Check if finding is in changed/affected code
        norm_changed = {p.replace("\\", "/").strip("/").lower() for p in changed}
        norm_affected = {p.replace("\\", "/").strip("/").lower() for p in affected}
        is_in_changed = norm_path in norm_changed or norm_path in norm_affected

        # 1. Policy change check (code unchanged)
        if policy_hash_changed and not is_in_changed:
            return RegressionClassification(
                cause=RegressionCause.POLICY_CHANGE,
                severity=RegressionSeverity.ADVISORY,
                is_in_changed_code=False,
                policy_id=policy_id,
                explanation=f"Finding induced by policy change{f' ({policy_id})' if policy_id else ''} in unchanged code",
            )

        # 2. Config change check (code unchanged)
        if rules_hash_changed and not is_in_changed:
            return RegressionClassification(
                cause=RegressionCause.CONFIG_CHANGE,
                severity=RegressionSeverity.ADVISORY,
                is_in_changed_code=False,
                config_scope="rules_hash",
                explanation="Finding surfaced due to analysis configuration change in unchanged code",
            )

        if cfg_dataflow_hash_changed and not is_in_changed:
            return RegressionClassification(
                cause=RegressionCause.CONFIG_CHANGE,
                severity=RegressionSeverity.ADVISORY,
                is_in_changed_code=False,
                config_scope="cfg_dataflow_hash",
                explanation="Finding surfaced due to dataflow configuration change in unchanged code",
            )

        # 3. Framework change check (code unchanged)
        if framework_model_hash_changed and not is_in_changed:
            return RegressionClassification(
                cause=RegressionCause.FRAMEWORK_CHANGE,
                severity=RegressionSeverity.ADVISORY,
                is_in_changed_code=False,
                explanation="Finding surfaced due to framework model update in unchanged code",
            )

        # 4. Code regression (in changed code, no config/policy change)
        if is_in_changed:
            regression_severity = _severity_to_regression_severity(sev_value)
            return RegressionClassification(
                cause=RegressionCause.CODE_CHANGE,
                severity=regression_severity,
                is_in_changed_code=True,
                changed_file_path=file_path,
                explanation=f"Security regression in modified code ({file_path})",
            )

        # 5. Pre-existing (unchanged code, no config/policy changes)
        return RegressionClassification(
            cause=RegressionCause.PRE_EXISTING,
            severity=RegressionSeverity.ADVISORY,
            is_in_changed_code=False,
            explanation="Finding in unchanged code; previously undetected or newly surfaced",
        )


def _severity_to_regression_severity(severity_value: str) -> RegressionSeverity:
    """Map finding severity to regression urgency."""
    if severity_value in ("CRITICAL", "HIGH"):
        return RegressionSeverity.BLOCKING
    elif severity_value == "MEDIUM":
        return RegressionSeverity.ACTIONABLE
    else:
        return RegressionSeverity.ADVISORY
