"""Scoped analysis configuration fingerprinting engine (Phase 21)."""

import hashlib
import json
from typing import Any, Optional

from analyzer.config.repo_config import RepoConfig
from analyzer.config.settings import AnalysisConfig
from analyzer.incremental.models import ConfigFingerprint


def canonical_json_digest(payload: Any) -> str:
    """Compute a deterministic SHA-256 digest of arbitrary configuration payload."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_scoped_config_fingerprint(
    config: Optional[Any] = None,
    repo_config: Optional[RepoConfig] = None,
) -> ConfigFingerprint:
    """Compute layer-scoped configuration digests from active AnalysisConfig or RepoConfig."""
    # Extract values normalizing across AnalysisConfig, RepoConfig, or dict
    if isinstance(config, AnalysisConfig):
        cfg = config
    else:
        cfg = AnalysisConfig()

    rc_analysis = repo_config.analysis if repo_config else None
    rc_paths = repo_config.paths if repo_config else None
    rc_reporting = repo_config.reporting if repo_config else None

    # Helper to resolve precedence (CLI/AnalysisConfig > RepoConfig > default)
    def _val(attr: str, default: Any) -> Any:
        v = getattr(cfg, attr, None)
        if v is not None:
            return v
        if rc_analysis is not None:
            v_rc = getattr(rc_analysis, attr, None)
            if v_rc is not None:
                return v_rc
        return default

    # 1. Parsing Scope
    parsing_payload = {
        "parser_version": "1.0.0",
        "supported_languages": ["PYTHON", "JAVASCRIPT", "TYPESCRIPT"],
    }
    parsing_hash = canonical_json_digest(parsing_payload)

    # 2. Dependency Scope
    exclude_paths = list(getattr(cfg, "paths_exclude", []))
    if rc_paths and rc_paths.exclude:
        for p in rc_paths.exclude:
            if p not in exclude_paths:
                exclude_paths.append(p)
    exclude_paths.sort()

    dependency_payload = {
        "max_component_depth": _val("max_component_depth", 2),
        "paths_exclude": exclude_paths,
    }
    dependency_hash = canonical_json_digest(dependency_payload)

    # 3. CFG and Data-Flow Scope
    cfg_dataflow_payload = {
        "max_active_paths": _val("max_active_paths", 8),
        "max_total_path_states": _val("max_total_path_states", 128),
        "max_branch_depth": _val("max_branch_depth", 6),
        "max_conditions_per_path": _val("max_conditions_per_path", 16),
        "max_cfg_blocks": _val("max_cfg_blocks", 64),
        "disable_path_sensitivity": _val("disable_path_sensitivity", False),
        "disable_guard_analysis": _val("disable_guard_analysis", False),
        "disable_alias_analysis": _val("disable_alias_analysis", False),
        "disable_field_sensitivity": _val("disable_field_sensitivity", False),
        "max_points_to_candidates": _val("max_points_to_candidates", 4),
        "max_fields_per_object": _val("max_fields_per_object", 16),
        "max_objects_per_function": _val("max_objects_per_function", 32),
        "max_alias_iterations": _val("max_alias_iterations", 5),
        "max_taint_depth": _val("max_taint_depth", 25),
    }
    cfg_dataflow_hash = canonical_json_digest(cfg_dataflow_payload)

    # 4. Call Graph Scope
    callgraph_payload = {
        "max_call_depth": _val("max_call_depth", 5),
        "interprocedural": _val("interprocedural", True),
        "disable_type_inference": _val("disable_type_inference", False),
        "disable_context_sensitivity": _val("disable_context_sensitivity", False),
        "max_k": _val("max_k", 2),
        "max_contexts_per_function": _val("max_contexts_per_function", 8),
        "max_summary_iterations": _val("max_summary_iterations", 5),
    }
    callgraph_hash = canonical_json_digest(callgraph_payload)

    # 5. Contract Scope
    contract_payload = {
        "disable_interprocedural_contracts": _val("disable_interprocedural_contracts", False),
        "max_cached_contracts": _val("max_cached_contracts", 2000),
        "max_effects_per_summary": _val("max_effects_per_summary", 16),
        "max_field_effect_depth": _val("max_field_effect_depth", 3),
    }
    contract_hash = canonical_json_digest(contract_payload)

    # 6. Contract Composition Scope
    composition_payload = {
        "disable_contract_composition": _val("disable_contract_composition", False),
        "max_contract_composition_depth": _val("max_contract_composition_depth", 5),
        "max_exception_contracts": _val("max_exception_contracts", 16),
        "max_contract_conflicts": _val("max_contract_conflicts", 32),
        "max_container_fields": _val("max_container_fields", 16),
        "max_project_contract_nodes": _val("max_project_contract_nodes", 1000),
    }
    composition_hash = canonical_json_digest(composition_payload)

    # 7. Rules Scope
    enabled_rules = getattr(cfg, "enabled_rules", None)
    if enabled_rules is None and rc_analysis and rc_analysis.enabled_rules:
        enabled_rules = rc_analysis.enabled_rules
    if enabled_rules is not None:
        enabled_rules = sorted(list(enabled_rules))

    disabled_rules = list(getattr(cfg, "disabled_rules", []))
    if rc_analysis and rc_analysis.disabled_rules:
        for r in rc_analysis.disabled_rules:
            if r not in disabled_rules:
                disabled_rules.append(r)
    disabled_rules.sort()

    rules_payload = {
        "enabled_rules": enabled_rules,
        "disabled_rules": disabled_rules,
        "fail_on": _val("fail_on", None),
        "fail_on_severity": _val("fail_on_severity", None),
        "centrality_threshold": _val("centrality_threshold", 0.35),
        "coupling_threshold": _val("coupling_threshold", 10),
        "god_module_loc": _val("god_module_loc", 800),
    }
    rules_hash = canonical_json_digest(rules_payload)

    # 8. Reporting Scope
    reporting_payload = {
        "format": rc_reporting.format if rc_reporting else "terminal",
        "output_file": rc_reporting.output_file if rc_reporting else None,
    }
    reporting_hash = canonical_json_digest(reporting_payload)

    # 9. Global Hash
    global_payload = {
        "parsing": parsing_payload,
        "dependency": dependency_payload,
        "cfg_dataflow": cfg_dataflow_payload,
        "callgraph": callgraph_payload,
        "contract": contract_payload,
        "composition": composition_payload,
        "rules": rules_payload,
        "reporting": reporting_payload,
    }
    global_hash = canonical_json_digest(global_payload)

    return ConfigFingerprint(
        global_hash=global_hash,
        parsing_hash=parsing_hash,
        dependency_hash=dependency_hash,
        cfg_dataflow_hash=cfg_dataflow_hash,
        callgraph_hash=callgraph_hash,
        contract_hash=contract_hash,
        composition_hash=composition_hash,
        rules_hash=rules_hash,
        reporting_hash=reporting_hash,
    )
