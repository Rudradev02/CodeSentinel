"""Analysis configuration schema and threshold settings for CodeSentinel."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from analyzer.models.findings import FindingSeverity


class OutputFormat(str, Enum):
    """Supported report output formats."""
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    MARKDOWN = "markdown"
    JUNIT = "junit"
    GITLAB = "gitlab"


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
    paths_exclude: list[str] = Field(
        default_factory=list,
        description="Explicit path patterns to exclude from ingestion.",
    )
    config_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 digest of active repository configuration.",
    )
    config_file_path: Optional[str] = Field(
        default=None,
        description="Path to discovered repository configuration file if any.",
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

    # Phase 7: Component Model & Architecture
    max_component_depth: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Maximum directory depth for component grouping.",
    )
    arc_007_stable_max_i: float = Field(
        default=0.30,
        ge=0.0,
        le=1.0,
        description="Maximum instability for a component to be classified as Stable in ARC-007.",
    )
    arc_007_unstable_min_i: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Minimum instability for a component to be classified as Unstable in ARC-007.",
    )
    arc_007_min_ca: int = Field(
        default=2,
        ge=0,
        description="Minimum afferent coupling required for Stable classification in ARC-007.",
    )

    # Phase 13: Centrality & Data-Flow
    arc_009_centrality_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Betweenness centrality threshold for ARC-009 bottleneck detection.",
    )
    max_taint_depth: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum propagation depth for intraprocedural taint tracking.",
    )
    # Phase 15: Interprocedural Call Graph & Taint Configuration
    max_call_depth: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum call depth for interprocedural taint propagation (Phase 15).",
    )
    disable_interprocedural: bool = Field(
        default=False,
        description="Disable interprocedural call graph construction and cross-function taint analysis (Phase 15).",
    )
    # Phase 16: Type-Aware & Context-Sensitive Propagation
    disable_type_inference: bool = Field(
        default=False,
        description="Disable conservative receiver type inference (Phase 16).",
    )
    disable_context_sensitivity: bool = Field(
        default=False,
        description="Disable context-sensitive call string tracking (Phase 16).",
    )
    max_k: int = Field(
        default=2,
        ge=1,
        le=2,
        description="Maximum call-string context suffix length (Phase 16).",
    )
    max_contexts_per_function: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Maximum contexts evaluated per function before widening (Phase 16).",
    )
    max_summary_iterations: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum fixed-point summary iterations for recursive SCCs (Phase 16).",
    )
    # Phase 17: Bounded Alias, Points-To & Field-Sensitive Analysis
    disable_alias_analysis: bool = Field(
        default=False,
        description="Disable alias and points-to analysis (falls back cleanly to Phase 16).",
    )
    disable_field_sensitivity: bool = Field(
        default=False,
        description="Disable field-sensitive state tracking (Phase 17).",
    )
    max_points_to_candidates: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Maximum points-to targets before widening (Phase 17).",
    )
    max_fields_per_object: int = Field(
        default=16,
        ge=1,
        le=64,
        description="Maximum fields tracked per abstract object (Phase 17).",
    )
    max_objects_per_function: int = Field(
        default=32,
        ge=1,
        le=128,
        description="Maximum abstract objects instantiated per function (Phase 17).",
    )
    max_alias_iterations: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum intraprocedural alias fixed-point iterations (Phase 17).",
    )
    # Phase 18: Bounded Path-Sensitive Control-Flow & Guard Analysis
    disable_path_sensitivity: bool = Field(
        default=False,
        description="Disable path-sensitive analysis (falls back cleanly to Phase 17).",
    )
    disable_guard_analysis: bool = Field(
        default=False,
        description="Disable guard and refinement reasoning (Phase 18).",
    )
    max_active_paths: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Maximum active exploration paths per function before widening (Phase 18).",
    )
    max_total_path_states: int = Field(
        default=128,
        ge=16,
        le=512,
        description="Maximum total path states explored per function (Phase 18).",
    )
    max_branch_depth: int = Field(
        default=6,
        ge=1,
        le=16,
        description="Maximum branch depth before path truncation (Phase 18).",
    )
    max_conditions_per_path: int = Field(
        default=16,
        ge=2,
        le=64,
        description="Maximum guard conditions accumulated per path (Phase 18).",
    )
    max_cfg_blocks: int = Field(
        default=64,
        ge=8,
        le=256,
        description="Maximum CFG basic blocks constructed per function (Phase 18).",
    )
    # Phase 19: Path-Sensitive Interprocedural Contracts & Function Summaries
    disable_interprocedural_contracts: bool = Field(
        default=False,
        description="Disable interprocedural contracts (falls back cleanly to Phase 18).",
    )
    max_cached_contracts: int = Field(
        default=2000,
        ge=100,
        le=10000,
        description="Maximum cached contract summaries before deterministic eviction (Phase 19).",
    )
    max_effects_per_summary: int = Field(
        default=16,
        ge=4,
        le=64,
        description="Maximum conditional effects extracted per function summary (Phase 19).",
    )
    max_field_effect_depth: int = Field(
        default=3,
        ge=1,
        le=8,
        description="Maximum field traversal depth for contract postconditions (Phase 19).",
    )
    # Phase 20: Project-Wide Contract Composition, Exception-Aware Data Flow & Security Boundary Reasoning
    disable_contract_composition: bool = Field(
        default=False,
        description="Disable contract composition and security boundary reasoning (Phase 20).",
    )
    max_contract_composition_depth: int = Field(
        default=5,
        ge=1,
        le=16,
        description="Maximum call chain depth for cross-function contract composition (Phase 20).",
    )
    max_exception_contracts: int = Field(
        default=16,
        ge=1,
        le=64,
        description="Maximum exceptional postcondition contracts per function (Phase 20).",
    )
    max_contract_conflicts: int = Field(
        default=32,
        ge=1,
        le=128,
        description="Maximum conflicting fact pairs recorded before widening (Phase 20).",
    )
    max_container_fields: int = Field(
        default=16,
        ge=1,
        le=64,
        description="Maximum dictionary/container fields tracked for contract refinements (Phase 20).",
    )
    max_project_contract_nodes: int = Field(
        default=1000,
        ge=50,
        le=10000,
        description="Maximum nodes retained in the project contract graph (Phase 20).",
    )

    # Phase 22: Context-Aware Security Intelligence, Cross-Module Data-Flow & Incremental Analysis Hardening
    enable_taint_summaries: bool = Field(
        default=True,
        description="Enable per-file taint summary extraction and caching (Phase 22).",
    )
    max_taint_summary_entries: int = Field(
        default=5000,
        ge=100,
        le=50000,
        description="Maximum per-file taint summary entries cached (Phase 22).",
    )
    enable_evidence_chains: bool = Field(
        default=True,
        description="Enable structured security evidence chain population in findings (Phase 22).",
    )
    max_evidence_chain_depth: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Maximum propagation steps retained in evidence chains (Phase 22).",
    )
    enable_contract_caching: bool = Field(
        default=True,
        description="Enable per-function contract caching at L7 (Phase 22).",
    )
    max_cached_contract_entries: int = Field(
        default=10000,
        ge=100,
        le=100000,
        description="Maximum individual function contracts cached at L7 (Phase 22).",
    )
    enable_composition_caching: bool = Field(
        default=True,
        description="Enable per-composition-edge caching at L8 (Phase 22).",
    )
    max_cached_composition_entries: int = Field(
        default=20000,
        ge=100,
        le=200000,
        description="Maximum composition edges cached at L8 (Phase 22).",
    )
    enable_selective_parsing: bool = Field(
        default=False,
        description="Enable selective parsing optimization in the pipeline (Phase 22). Experimental.",
    )

    # Phase 23: Security Boundary Semantics, Framework-Aware Analysis & Policy Intelligence
    enable_boundary_detection: bool = Field(
        default=True,
        description="Enable framework trust boundary detection (Phase 23).",
    )
    max_security_boundaries: int = Field(
        default=5000,
        ge=100,
        le=50000,
        description="Maximum security boundaries retained per repository (Phase 23).",
    )
    enable_policy_engine: bool = Field(
        default=True,
        description="Enable security policy engine evaluation on data-flow findings (Phase 23).",
    )
    max_policy_paths: int = Field(
        default=10000,
        ge=100,
        le=100000,
        description="Maximum policy paths evaluated per analysis (Phase 23).",
    )
    policy_mode: str = Field(
        default="ENFORCE",
        description="Execution mode for security policies: ENFORCE, ADVISORY, or DISABLED (Phase 23).",
    )

    # Reporting and Policy
    output_format: OutputFormat = Field(
        default=OutputFormat.TERMINAL,
        description="Format for analysis reporting: terminal, json, or sarif.",
    )
    output_file: Optional[str] = Field(
        default=None,
        description="Optional filesystem path to write the formatted report to.",
    )
    fail_on_severity: Optional[FindingSeverity] = Field(
        default=None,
        description="Minimum severity threshold to trigger a non-zero policy exit code (exit 2).",
    )
    baseline_path: Optional[str] = Field(
        default=None,
        description="Path to baseline report JSON file for differential comparison.",
    )
    fail_on_regression: Optional[FindingSeverity] = Field(
        default=None,
        description="Minimum severity threshold for newly introduced findings to trigger policy exit code 2.",
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
            if v_clean == "sarif":
                return OutputFormat.SARIF
            if v_clean == "html":
                return OutputFormat.HTML
            if v_clean in ("markdown", "md"):
                return OutputFormat.MARKDOWN
            if v_clean == "junit":
                return OutputFormat.JUNIT
            if v_clean in ("gitlab", "codequality"):
                return OutputFormat.GITLAB
            valid_opts = [f.value for f in OutputFormat]
            raise ValueError(f"Invalid output format: '{v}'. Must be one of: {valid_opts}")
        return v

    @field_validator("fail_on_severity", "fail_on_regression", mode="before")
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
                    f"Invalid severity value: '{v}'. Valid options are: {', '.join(valid_severities)}"
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
