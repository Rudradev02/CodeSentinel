"""Rule pack and hierarchical policy composition models (Phase 26)."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.compliance.models import ComplianceFramework
from analyzer.models.findings import FindingSeverity
from analyzer.rules.policy import SecurityPolicy


class RuleOverride(BaseModel):
    """Explicit configuration override applied to a static analysis rule."""
    model_config = ConfigDict(frozen=True)

    rule_id: str
    enabled: Optional[bool] = None
    severity_override: Optional[FindingSeverity] = None
    parameter_overrides: dict[str, Any] = Field(default_factory=dict)


class RulePack(BaseModel):
    """Reusable, composable bundle of rules, policies, and compliance mappings."""
    model_config = ConfigDict(frozen=True)

    pack_id: str                         # e.g., "pci-dss-v4", "org-baseline"
    version: str = "1.0.0"
    name: str
    description: str = ""
    extends: list[str] = Field(default_factory=list) # Parent pack IDs or paths
    compliance_frameworks: list[ComplianceFramework] = Field(default_factory=list)
    rule_overrides: list[RuleOverride] = Field(default_factory=list)
    policies: list[SecurityPolicy] = Field(default_factory=list)
    disallow_inline_suppressions: bool = False       # Enterprise constraint: forbid inline comments
    allow_repo_override: bool = True                 # If False, child packs/repos cannot relax this pack's rules
    gate_policy: Optional[dict[str, Any]] = None     # Optional default CI/CD gate policy
