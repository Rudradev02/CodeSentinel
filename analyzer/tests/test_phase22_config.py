"""Unit tests for Phase 22 configuration extensions and scoped fingerprinting."""

import pytest
from pydantic import ValidationError

from analyzer.config.settings import AnalysisConfig
from analyzer.incremental.config_fingerprint import compute_scoped_config_fingerprint
from analyzer.incremental.models import IncrementalStats


def test_phase22_config_defaults():
    """Verify Phase 22 configuration fields have sound, backward-compatible defaults."""
    cfg = AnalysisConfig()

    # Taint summaries
    assert cfg.enable_taint_summaries is True
    assert cfg.max_taint_summary_entries == 5000

    # Evidence chains
    assert cfg.enable_evidence_chains is True
    assert cfg.max_evidence_chain_depth == 10

    # Contract caching (L7)
    assert cfg.enable_contract_caching is True
    assert cfg.max_cached_contract_entries == 10000

    # Composition caching (L8)
    assert cfg.enable_composition_caching is True
    assert cfg.max_cached_composition_entries == 20000

    # Selective parsing
    assert cfg.enable_selective_parsing is False


def test_phase22_config_bounds():
    """Verify constraint boundaries on numeric Phase 22 config fields."""
    with pytest.raises(ValidationError):
        AnalysisConfig(max_taint_summary_entries=50)  # ge=100

    with pytest.raises(ValidationError):
        AnalysisConfig(max_evidence_chain_depth=0)  # ge=1

    with pytest.raises(ValidationError):
        AnalysisConfig(max_evidence_chain_depth=25)  # le=20

    with pytest.raises(ValidationError):
        AnalysisConfig(max_cached_contract_entries=50)  # ge=100

    with pytest.raises(ValidationError):
        AnalysisConfig(max_cached_composition_entries=50)  # ge=100


def test_phase22_fingerprint_scoped_invalidation():
    """Verify that scoped fingerprint hashes change only in their intended scope."""
    base_cfg = AnalysisConfig()
    base_fp = compute_scoped_config_fingerprint(base_cfg)

    # 1. Mutate taint summaries config -> cfg_dataflow_hash must change, contract_hash must not
    taint_cfg = AnalysisConfig(enable_taint_summaries=False)
    taint_fp = compute_scoped_config_fingerprint(taint_cfg)
    assert taint_fp.cfg_dataflow_hash != base_fp.cfg_dataflow_hash
    assert taint_fp.contract_hash == base_fp.contract_hash
    assert taint_fp.rules_hash == base_fp.rules_hash
    assert taint_fp.global_hash != base_fp.global_hash

    # 2. Mutate contract caching config -> contract_hash must change, rules_hash must not
    contract_cfg = AnalysisConfig(enable_contract_caching=False)
    contract_fp = compute_scoped_config_fingerprint(contract_cfg)
    assert contract_fp.contract_hash != base_fp.contract_hash
    assert contract_fp.rules_hash == base_fp.rules_hash
    assert contract_fp.composition_hash == base_fp.composition_hash
    assert contract_fp.global_hash != base_fp.global_hash

    # 3. Mutate composition caching config -> composition_hash must change, callgraph_hash must not
    comp_cfg = AnalysisConfig(enable_composition_caching=False)
    comp_fp = compute_scoped_config_fingerprint(comp_cfg)
    assert comp_fp.composition_hash != base_fp.composition_hash
    assert comp_fp.callgraph_hash == base_fp.callgraph_hash
    assert comp_fp.rules_hash == base_fp.rules_hash
    assert comp_fp.global_hash != base_fp.global_hash

    # 4. Mutate evidence chains config -> rules_hash must change, cfg_dataflow_hash must not
    ev_cfg = AnalysisConfig(enable_evidence_chains=False)
    ev_fp = compute_scoped_config_fingerprint(ev_cfg)
    assert ev_fp.rules_hash != base_fp.rules_hash
    assert ev_fp.cfg_dataflow_hash == base_fp.cfg_dataflow_hash
    assert ev_fp.contract_hash == base_fp.contract_hash
    assert ev_fp.global_hash != base_fp.global_hash

    # 5. Mutate selective parsing -> global_hash must change
    sel_cfg = AnalysisConfig(enable_selective_parsing=True)
    sel_fp = compute_scoped_config_fingerprint(sel_cfg)
    assert sel_fp.global_hash != base_fp.global_hash


def test_phase22_incremental_stats_telemetry():
    """Verify new Phase 22 telemetry counters in IncrementalStats."""
    stats = IncrementalStats(
        composition_hits=5,
        composition_misses=2,
        taint_summary_hits=10,
        taint_summary_misses=1,
    )
    assert stats.composition_hits == 5
    assert stats.composition_misses == 2
    assert stats.taint_summary_hits == 10
    assert stats.taint_summary_misses == 1
