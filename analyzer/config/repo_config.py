"""Declarative repository-level configuration schema for CodeSentinel (.codesentinel.yml)."""

import hashlib
import json
import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


RULE_ID_PATTERN = re.compile(r"^(SEC-[A-Z]+-[0-9]{3}|ARC-[0-9]{3})$")
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_FORMATS = {"terminal", "json", "sarif", "html", "markdown", "junit", "gitlab"}


class AnalysisSectionConfig(BaseModel):
    """Configuration section for static analysis rules and architectural thresholds."""
    model_config = ConfigDict(extra="forbid")

    enabled_rules: Optional[list[str]] = Field(
        default=None,
        description="Explicit list of active rule IDs. If None, all registered rules (except disabled) are active.",
    )
    disabled_rules: list[str] = Field(
        default_factory=list,
        description="Explicit list of deactivated rule IDs.",
    )
    fail_on: Optional[str] = Field(
        default=None,
        description="Severity threshold to trigger policy failure exit code (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
    )
    fail_on_severity: Optional[str] = Field(
        default=None,
        description="Alias for fail_on.",
    )
    max_component_depth: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Maximum directory depth for subsystem component aggregation (default: 2).",
    )
    centrality_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Betweenness centrality threshold for ARC-009 bottleneck detection (default: 0.35).",
    )
    max_taint_depth: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum propagation depth for intraprocedural taint analysis (default: 25).",
    )
    max_call_depth: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum call depth for interprocedural taint analysis (default: 5).",
    )
    interprocedural: bool = Field(
        default=True,
        description="Enable interprocedural call graph and cross-function taint analysis (default: true).",
    )
    disable_type_inference: bool = Field(
        default=False,
        description="Disable conservative receiver type inference (default: false).",
    )
    disable_context_sensitivity: bool = Field(
        default=False,
        description="Disable context-sensitive call string tracking (default: false).",
    )
    max_k: int = Field(
        default=2,
        ge=1,
        le=2,
        description="Maximum call-string context suffix length (default: 2, max: 2).",
    )
    max_contexts_per_function: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Maximum contexts evaluated per function before widening (default: 8).",
    )
    max_summary_iterations: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum fixed-point summary iterations for recursive SCCs (default: 5).",
    )
    disable_alias_analysis: bool = Field(
        default=False,
        description="Disable alias and points-to analysis (default: false).",
    )
    disable_field_sensitivity: bool = Field(
        default=False,
        description="Disable field-sensitive state tracking (default: false).",
    )
    max_points_to_candidates: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Maximum points-to targets before widening (default: 4).",
    )
    max_fields_per_object: int = Field(
        default=16,
        ge=1,
        le=64,
        description="Maximum tracked fields per abstract object (default: 16).",
    )
    max_objects_per_function: int = Field(
        default=32,
        ge=1,
        le=128,
        description="Maximum abstract objects per function scope (default: 32).",
    )
    max_alias_iterations: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum fixed-point iterations for alias resolution (default: 5).",
    )
    # Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis
    disable_path_sensitivity: bool = Field(
        default=False,
        description="Disable path-sensitive analysis (default: false).",
    )
    disable_guard_analysis: bool = Field(
        default=False,
        description="Disable guard and refinement reasoning (default: false).",
    )
    max_active_paths: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Maximum active exploration paths per function (default: 8).",
    )
    max_total_path_states: int = Field(
        default=128,
        ge=16,
        le=512,
        description="Maximum total path states per function (default: 128).",
    )
    max_branch_depth: int = Field(
        default=6,
        ge=1,
        le=16,
        description="Maximum branch depth before truncation (default: 6).",
    )
    max_conditions_per_path: int = Field(
        default=16,
        ge=2,
        le=64,
        description="Maximum guard conditions per path (default: 16).",
    )
    max_cfg_blocks: int = Field(
        default=64,
        ge=8,
        le=256,
        description="Maximum CFG blocks per function (default: 64).",
    )
    # Phase 19: Path-Sensitive Interprocedural Contracts & Function Summaries
    disable_interprocedural_contracts: bool = Field(
        default=False,
        description="Disable interprocedural contracts (default: false).",
    )
    max_cached_contracts: int = Field(
        default=2000,
        ge=100,
        le=10000,
        description="Maximum cached contract summaries before deterministic eviction (default: 2000).",
    )
    max_effects_per_summary: int = Field(
        default=16,
        ge=4,
        le=64,
        description="Maximum conditional effects extracted per function summary (default: 16).",
    )
    max_field_effect_depth: int = Field(
        default=3,
        ge=1,
        le=8,
        description="Maximum field traversal depth for contract postconditions (default: 3).",
    )
    coupling_threshold: int = Field(
        default=10,
        ge=1,
        description="Efferent coupling threshold for ARC-002 fan-out detection.",
    )
    god_module_loc: int = Field(
        default=500,
        ge=50,
        description="Primary lines of code threshold for ARC-003 God Module detection.",
    )

    @field_validator("enabled_rules", "disabled_rules")
    @classmethod
    def validate_rule_ids(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        cleaned = []
        for r in v:
            r_str = str(r).strip()
            if not RULE_ID_PATTERN.match(r_str):
                raise ValueError(f"Invalid rule identifier '{r_str}'. Expected format SEC-[LANG]-[0-9]{{3}} or ARC-[0-9]{{3}}.")
            cleaned.append(r_str)
        return cleaned

    @field_validator("fail_on", "fail_on_severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_upper = v.strip().upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(list(VALID_SEVERITIES))}")
        return v_upper

    @model_validator(mode="after")
    def sync_and_validate_analysis(self) -> "AnalysisSectionConfig":
        if self.fail_on and not self.fail_on_severity:
            self.fail_on_severity = self.fail_on
        elif self.fail_on_severity and not self.fail_on:
            self.fail_on = self.fail_on_severity
        return self


    @model_validator(mode="after")
    def validate_no_overlap(self) -> "AnalysisSectionConfig":
        if self.enabled_rules is not None and self.disabled_rules:
            overlap = set(self.enabled_rules).intersection(set(self.disabled_rules))
            if overlap:
                raise ValueError(f"Rule configuration conflict: rule(s) {sorted(list(overlap))} cannot be both enabled and disabled.")
        return self


class PathsSectionConfig(BaseModel):
    """Configuration section for path inclusions and exclusions."""
    model_config = ConfigDict(extra="forbid")

    exclude: list[str] = Field(
        default_factory=list,
        description="Glob patterns of files or directories to exclude from analysis.",
    )
    include: list[str] = Field(
        default_factory=list,
        description="Optional glob patterns to explicitly restrict analysis scope.",
    )

    @field_validator("exclude", "include")
    @classmethod
    def sanitize_paths(cls, v: list[str]) -> list[str]:
        cleaned = []
        for p in v:
            p_str = str(p).strip().replace("\\", "/")
            if ".." in p_str.split("/"):
                raise ValueError(f"Path traversal detected in pattern '{p}'. Parent directory references ('..') are prohibited.")
            cleaned.append(p_str)
        return cleaned


class ComparisonSectionConfig(BaseModel):
    """Configuration section for differential baseline comparison."""
    model_config = ConfigDict(extra="forbid")

    baseline: Optional[str] = Field(
        default=None,
        description="Path to default baseline JSON report file.",
    )
    fail_on_regression: Optional[str] = Field(
        default=None,
        description="Severity threshold for newly introduced findings to trigger policy exit code 2.",
    )

    @field_validator("fail_on_regression")
    @classmethod
    def validate_regression_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_upper = v.strip().upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid regression severity '{v}'. Must be one of: {sorted(list(VALID_SEVERITIES))}")
        return v_upper


class ReportingSectionConfig(BaseModel):
    """Configuration section for reporting output format and destination."""
    model_config = ConfigDict(extra="forbid")

    format: str = Field(
        default="terminal",
        description="Default output report format (terminal, json, sarif, html, markdown, junit, gitlab).",
    )
    output_file: Optional[str] = Field(
        default=None,
        description="Default output file path to write report to.",
    )
    category: Optional[str] = Field(
        default=None,
        description="Default finding category filter (SECURITY or ARCHITECTURE).",
    )
    severity: Optional[str] = Field(
        default=None,
        description="Default finding minimum severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
    )

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        v_lower = v.strip().lower()
        if v_lower not in VALID_FORMATS:
            raise ValueError(f"Invalid output format '{v}'. Must be one of: {sorted(list(VALID_FORMATS))}")
        return v_lower

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_upper = v.strip().upper()
        if v_upper not in {"SECURITY", "ARCHITECTURE"}:
            raise ValueError(f"Invalid reporting category '{v}'. Must be 'SECURITY' or 'ARCHITECTURE'.")
        return v_upper

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_upper = v.strip().upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid reporting severity '{v}'. Must be one of: {sorted(list(VALID_SEVERITIES))}")
        return v_upper



class RepoConfig(BaseModel):
    """Root model for .codesentinel.yml declarative repository configuration."""
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, description="Configuration schema version (must be 1).")
    analysis: AnalysisSectionConfig = Field(default_factory=AnalysisSectionConfig)
    paths: PathsSectionConfig = Field(default_factory=PathsSectionConfig)
    comparison: ComparisonSectionConfig = Field(default_factory=ComparisonSectionConfig)
    reporting: ReportingSectionConfig = Field(default_factory=ReportingSectionConfig)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"Unsupported configuration schema version: {v}. Supported versions: [1].")
        return v

    def compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash digest of the normalized configuration."""
        data = {
            "version": self.version,
            "analysis": {
                "enabled_rules": sorted(self.analysis.enabled_rules) if self.analysis.enabled_rules else None,
                "disabled_rules": sorted(self.analysis.disabled_rules),
                "fail_on_severity": self.analysis.fail_on_severity,
                "max_component_depth": self.analysis.max_component_depth,
                "centrality_threshold": self.analysis.centrality_threshold,
                "max_taint_depth": self.analysis.max_taint_depth,
                "max_call_depth": self.analysis.max_call_depth,
                "interprocedural": self.analysis.interprocedural,
                "disable_type_inference": self.analysis.disable_type_inference,
                "disable_context_sensitivity": self.analysis.disable_context_sensitivity,
                "max_k": self.analysis.max_k,
                "max_contexts_per_function": self.analysis.max_contexts_per_function,
                "max_summary_iterations": self.analysis.max_summary_iterations,
                "disable_path_sensitivity": self.analysis.disable_path_sensitivity,
                "disable_guard_analysis": self.analysis.disable_guard_analysis,
                "max_active_paths": self.analysis.max_active_paths,
                "max_total_path_states": self.analysis.max_total_path_states,
                "max_branch_depth": self.analysis.max_branch_depth,
                "max_conditions_per_path": self.analysis.max_conditions_per_path,
                "max_cfg_blocks": self.analysis.max_cfg_blocks,
                "coupling_threshold": self.analysis.coupling_threshold,
                "god_module_loc": self.analysis.god_module_loc,
            },
            "paths": {
                "exclude": sorted(self.paths.exclude),
                "include": sorted(self.paths.include),
            },
            "comparison": {
                "baseline": self.comparison.baseline,
                "fail_on_regression": self.comparison.fail_on_regression,
            },
            "reporting": {
                "format": self.reporting.format,
                "output_file": self.reporting.output_file,
            },
        }
        canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
