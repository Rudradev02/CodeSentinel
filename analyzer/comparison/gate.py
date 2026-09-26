"""CI/CD regression gate evaluation engine for CodeSentinel (Phase 25).

Evaluates differential findings against a configurable gate policy to
produce machine-readable PASS / FAIL / WARN verdicts for CI pipelines.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class GateVerdict(str, Enum):
    """CI/CD gate evaluation outcome."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class RegressionGatePolicy(BaseModel):
    """Configurable CI/CD gate policy for security regression checks.

    Controls which finding categories cause pipeline failure, which are
    treated as warnings, and which are silently ignored.
    """
    model_config = ConfigDict(frozen=True)

    fail_on_new_critical: bool = Field(default=True, description="Fail on new CRITICAL findings")
    fail_on_new_high: bool = Field(default=True, description="Fail on new HIGH findings")
    fail_on_new_medium: bool = Field(default=False, description="Fail on new MEDIUM findings")
    ignore_policy_induced: bool = Field(default=True, description="Ignore POLICY_INDUCED_NEW findings")
    ignore_pre_existing: bool = Field(default=True, description="Ignore PRE_EXISTING findings")
    ignore_suppressed: bool = Field(default=True, description="Ignore SUPPRESSED/DEFERRED findings")
    max_new_findings: Optional[int] = Field(default=None, ge=0, description="Max total new findings before failure")
    max_new_security_findings: Optional[int] = Field(default=None, ge=0, description="Max new security findings before failure")


class RegressionGateResult(BaseModel):
    """Result of evaluating a regression gate policy against differential findings."""

    verdict: GateVerdict = Field(..., description="Overall gate verdict")
    blocking_findings: list[dict] = Field(default_factory=list, description="Findings causing FAIL")
    advisory_findings: list[dict] = Field(default_factory=list, description="Warning-level findings")
    suppressed_findings: list[dict] = Field(default_factory=list, description="Findings suppressed by policy")
    ignored_findings: list[dict] = Field(default_factory=list, description="Findings ignored by gate policy")
    total_new: int = Field(default=0, ge=0)
    total_blocking: int = Field(default=0, ge=0)
    summary: str = Field(default="", description="Human-readable summary")


def evaluate_regression_gate(
    differential_findings: list[object],
    gate_policy: Optional[RegressionGatePolicy] = None,
) -> RegressionGateResult:
    """Evaluate differential findings against a regression gate policy.

    Filters findings by lifecycle state, regression cause, and severity
    to produce a machine-readable gate verdict.

    Args:
        differential_findings: List of DifferentialFinding instances.
        gate_policy: Gate policy configuration. Defaults to standard policy.

    Returns:
        RegressionGateResult with verdict and categorized findings.
    """
    policy = gate_policy or RegressionGatePolicy()

    blocking: list[dict] = []
    advisory: list[dict] = []
    suppressed: list[dict] = []
    ignored: list[dict] = []

    for df in differential_findings:
        transition = getattr(df, "transition", None)
        transition_value = transition.value if hasattr(transition, "value") else str(transition or "")

        # Only evaluate NEW or MODIFIED findings
        if transition_value not in ("NEW", "MODIFIED"):
            continue

        finding = getattr(df, "finding", None)
        if finding is None:
            continue

        lifecycle_state = getattr(df, "lifecycle_state", None)
        lifecycle_value = lifecycle_state.value if hasattr(lifecycle_state, "value") else str(lifecycle_state or "")

        regression = getattr(df, "regression", None)
        suppression = getattr(df, "suppression", None)

        finding_severity = getattr(finding, "severity", None)
        sev_value = finding_severity.value if hasattr(finding_severity, "value") else str(finding_severity or "")

        finding_info = {
            "rule_id": getattr(finding, "rule_id", "UNKNOWN"),
            "file_path": getattr(getattr(finding, "location", None), "file_path", ""),
            "severity": sev_value,
            "lifecycle_state": lifecycle_value,
        }

        # Check suppression
        if suppression is not None and policy.ignore_suppressed:
            suppressed.append(finding_info)
            continue

        # Check lifecycle-based ignores
        if lifecycle_value == "SUPPRESSED" and policy.ignore_suppressed:
            suppressed.append(finding_info)
            continue
        if lifecycle_value == "DEFERRED" and policy.ignore_suppressed:
            suppressed.append(finding_info)
            continue

        # Check policy-induced ignore
        if lifecycle_value == "POLICY_INDUCED_NEW" and policy.ignore_policy_induced:
            ignored.append(finding_info)
            continue

        # Check pre-existing ignore
        regression_cause = getattr(regression, "cause", None)
        cause_value = regression_cause.value if hasattr(regression_cause, "value") else str(regression_cause or "")

        if cause_value == "PRE_EXISTING" and policy.ignore_pre_existing:
            ignored.append(finding_info)
            continue

        # Evaluate severity-based blocking
        is_blocking = False
        if sev_value == "CRITICAL" and policy.fail_on_new_critical:
            is_blocking = True
        elif sev_value == "HIGH" and policy.fail_on_new_high:
            is_blocking = True
        elif sev_value == "MEDIUM" and policy.fail_on_new_medium:
            is_blocking = True

        if is_blocking:
            blocking.append(finding_info)
        else:
            advisory.append(finding_info)

    # Check absolute thresholds
    total_new = len(blocking) + len(advisory)
    threshold_exceeded = False

    if policy.max_new_findings is not None and total_new > policy.max_new_findings:
        threshold_exceeded = True
    if policy.max_new_security_findings is not None and total_new > policy.max_new_security_findings:
        threshold_exceeded = True

    # Determine verdict
    if blocking or threshold_exceeded:
        verdict = GateVerdict.FAIL
    elif advisory:
        verdict = GateVerdict.WARN
    else:
        verdict = GateVerdict.PASS

    summary_parts = []
    if blocking:
        summary_parts.append(f"{len(blocking)} blocking finding(s)")
    if advisory:
        summary_parts.append(f"{len(advisory)} advisory finding(s)")
    if suppressed:
        summary_parts.append(f"{len(suppressed)} suppressed")
    if ignored:
        summary_parts.append(f"{len(ignored)} ignored by policy")

    summary = f"Gate {verdict.value}: {', '.join(summary_parts)}" if summary_parts else f"Gate {verdict.value}: No actionable findings"

    return RegressionGateResult(
        verdict=verdict,
        blocking_findings=blocking,
        advisory_findings=advisory,
        suppressed_findings=suppressed,
        ignored_findings=ignored,
        total_new=total_new,
        total_blocking=len(blocking),
        summary=summary,
    )
