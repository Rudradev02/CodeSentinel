"""Analysis configuration schema and threshold settings for CodeSentinel."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from analyzer.models.findings import FindingSeverity


class OutputFormat(str, Enum):
    """Supported report output formats."""
    TERMINAL = "terminal"
    JSON = "json"


class AnalysisConfig(BaseModel):
    """Configuration model defining rule activation, architectural thresholds, and reporting policies.
    
    Represents purely configuration data; rule ID existence validation is deferred
    to the rule registry/application boundary where the active registry is available.
    """
    enabled_rules: Optional[list[str]] = Field(
        default=None,
        description="Explicit whitelist of active rule IDs. If None, all registered rules (except disabled) are active.",
    )
    disabled_rules: list[str] = Field(
        default_factory=list,
        description="Explicit blacklist of inactive rule IDs.",
    )

    # ARC-002: Excessive Fan-Out Coupling
    arc_002_coupling_threshold: int = Field(
        default=10,
        ge=1,
        description="Efferent coupling threshold for ARC-002 (fan-out exceeding this raises finding).",
    )

    # ARC-003: God Module Smell
    arc_003_loc_threshold: int = Field(
        default=500,
        ge=1,
        description="Primary LOC threshold for ARC-003 (condition 1: LOC > threshold, fan-out > threshold, fan-in > threshold).",
    )
    arc_003_fan_out_threshold: int = Field(
        default=8,
        ge=1,
        description="Primary efferent coupling threshold for ARC-003 condition 1.",
    )
    arc_003_fan_in_threshold: int = Field(
        default=5,
        ge=1,
        description="Primary afferent coupling threshold for ARC-003 condition 1.",
    )
    arc_003_loc_threshold_2: int = Field(
        default=800,
        ge=1,
        description="Secondary LOC threshold for ARC-003 condition 2 (extreme size with high fan-out).",
    )
    arc_003_fan_out_threshold_2: int = Field(
        default=10,
        ge=1,
        description="Secondary fan-out threshold for ARC-003 condition 2.",
    )

    # ARC-004: Deep Dependency Chain
    arc_004_depth_threshold: int = Field(
        default=5,
        ge=1,
        description="Maximum allowed transitive dependency hops in condensed local DAG.",
    )

    # Reporting and Policy
    output_format: OutputFormat = Field(
        default=OutputFormat.TERMINAL,
        description="Format for analysis reporting: terminal or json.",
    )
    output_file: Optional[str] = Field(
        default=None,
        description="Optional filesystem path to write the formatted report to.",
    )
    fail_on_severity: Optional[FindingSeverity] = Field(
        default=None,
        description="Minimum severity threshold to trigger a non-zero policy exit code (exit 2).",
    )

    @field_validator("output_format", mode="before")
    @classmethod
    def normalize_output_format(cls, v: str | OutputFormat) -> OutputFormat:
        if isinstance(v, str):
            v_clean = v.strip().lower()
            if v_clean in ("terminal", "text"):
                return OutputFormat.TERMINAL
            if v_clean == "json":
                return OutputFormat.JSON
            raise ValueError(f"Invalid output format: '{v}'. Must be 'terminal' or 'json'.")
        return v

    @field_validator("fail_on_severity", mode="before")
    @classmethod
    def normalize_fail_on_severity(cls, v: Optional[str | FindingSeverity]) -> Optional[FindingSeverity]:
        if v is None:
            return None
        if isinstance(v, str):
            v_upper = v.strip().upper()
            try:
                return FindingSeverity(v_upper)
            except ValueError:
                valid_severities = [s.value for s in FindingSeverity]
                raise ValueError(
                    f"Invalid fail_on_severity: '{v}'. Valid options are: {', '.join(valid_severities)}"
                )
        return v

    @model_validator(mode="after")
    def validate_rule_conflicts(self) -> "AnalysisConfig":
        """Ensure no rule ID is both explicitly enabled and explicitly disabled."""
        if self.enabled_rules is not None and self.disabled_rules:
            enabled_set = set(r.strip() for r in self.enabled_rules)
            disabled_set = set(r.strip() for r in self.disabled_rules)
            conflicts = enabled_set.intersection(disabled_set)
            if conflicts:
                sorted_conflicts = sorted(list(conflicts))
                raise ValueError(
                    f"Rule configuration conflict: rule(s) {sorted_conflicts} cannot be simultaneously "
                    "enabled and disabled."
                )
        return self
