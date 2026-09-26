"""Unit tests for Phase 22 L8 per-composition-edge cache."""

from pathlib import Path

from analyzer.dataflow.contracts.composition import (
    CompatibilityState,
    ContractCompositionEdge,
    ContractGuarantee,
    ContractRequirement,
)
from analyzer.dataflow.contracts.models import FunctionContract
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache, NullAnalysisCache
from analyzer.incremental.composition_cache import (
    compute_composition_cache_key,
    get_cached_composition_edge,
    set_cached_composition_edge,
)
from analyzer.incremental.contract_invalidation import (
    compute_versioned_contract_hash,
    should_prune_caller_reanalysis,
)


def _make_sample_edge() -> ContractCompositionEdge:
    return ContractCompositionEdge(
        guarantee=ContractGuarantee(
            contract_id="auth.sanitize:ROOT",
            producer_qn="auth.sanitize",
            producer_file="auth/sanitize.py",
            target_symbol="clean_data",
        ),
        requirement=ContractRequirement(
            contract_id="db.query:ROOT",
            consumer_qn="db.query",
            consumer_file="db/query.py",
            target_param_index=0,
            target_param_name="sql_text",
        ),
        compatibility=CompatibilityState.SATISFIED,
        governing_path="True",
        details="Taint-free guarantee satisfies non-tainted query requirement",
    )


def test_compute_composition_cache_key_determinism():
    """Verify L8 composition cache key derivation is deterministic."""
    k1 = compute_composition_cache_key("caller_h1", "callee_h1", "comp_cfg_1", "SEC-PY-001")
    k2 = compute_composition_cache_key("caller_h1", "callee_h1", "comp_cfg_1", "SEC-PY-001")
    assert k1 == k2
    assert len(k1) == 64


def test_compute_composition_cache_key_sensitivity():
    """Verify cache key changes when any participant contract or config changes."""
    base_k = compute_composition_cache_key("caller_h1", "callee_h1", "comp_cfg_1", "SEC-PY-001")

    # Change caller
    assert compute_composition_cache_key("caller_h2", "callee_h1", "comp_cfg_1", "SEC-PY-001") != base_k

    # Change callee
    assert compute_composition_cache_key("caller_h1", "callee_h2", "comp_cfg_1", "SEC-PY-001") != base_k

    # Change composition config
    assert compute_composition_cache_key("caller_h1", "callee_h1", "comp_cfg_2", "SEC-PY-001") != base_k

    # Change boundary rule ID
    assert compute_composition_cache_key("caller_h1", "callee_h1", "comp_cfg_1", "SEC-PY-002") != base_k


def test_set_and_get_cached_composition_edge_in_memory():
    """Verify storing and retrieving a ContractCompositionEdge in InMemoryAnalysisCache."""
    cache = InMemoryAnalysisCache()
    edge = _make_sample_edge()

    ok = set_cached_composition_edge(
        cache=cache,
        caller_contract_hash="caller_v1",
        callee_contract_hash="callee_v1",
        composition_config_hash="comp_cfg_v1",
        edge=edge,
        boundary_rule_id="SEC-PY-001",
    )
    assert ok is True

    cached = get_cached_composition_edge(
        cache=cache,
        caller_contract_hash="caller_v1",
        callee_contract_hash="callee_v1",
        composition_config_hash="comp_cfg_v1",
        boundary_rule_id="SEC-PY-001",
    )
    assert cached is not None
    assert cached.compatibility == CompatibilityState.SATISFIED
    assert cached.guarantee.producer_qn == "auth.sanitize"
    assert cached.requirement.consumer_qn == "db.query"


def test_composition_pruning_optimization():
    """Demonstrate L8 edge reuse enabled by should_prune_caller_reanalysis."""
    cache = InMemoryAnalysisCache()
    cfg_hash = "comp_cfg_v1"

    # Suppose callee has a body change, but contract semantics are unchanged
    callee_contract_v1 = FunctionContract(qualified_name="auth.sanitize", file_path="auth/sanitize.py")
    callee_contract_v2 = FunctionContract(qualified_name="auth.sanitize", file_path="auth/sanitize.py")

    assert should_prune_caller_reanalysis(callee_contract_v1, callee_contract_v2, cfg_hash) is True

    caller_contract = FunctionContract(qualified_name="views.handle", file_path="views/handle.py")
    caller_hash = compute_versioned_contract_hash(caller_contract, cfg_hash)
    callee_hash = compute_versioned_contract_hash(callee_contract_v1, cfg_hash)

    # Store edge for v1
    edge = _make_sample_edge()
    set_cached_composition_edge(cache, caller_hash, callee_hash, cfg_hash, edge)

    # For v2, callee_hash is identical, so cached edge is valid and reused
    callee_hash_v2 = compute_versioned_contract_hash(callee_contract_v2, cfg_hash)
    cached_edge = get_cached_composition_edge(cache, caller_hash, callee_hash_v2, cfg_hash)
    assert cached_edge is not None
    assert cached_edge.compatibility == CompatibilityState.SATISFIED


def test_composition_cache_disk_persistence(tmp_path: Path):
    """Verify L8 composition edge persists across DiskAnalysisCache instances."""
    cache1 = DiskAnalysisCache(cache_dir=tmp_path)
    edge = _make_sample_edge()

    set_cached_composition_edge(
        cache=cache1,
        caller_contract_hash="c_hash",
        callee_contract_hash="cal_hash",
        composition_config_hash="cfg_hash",
        edge=edge,
    )

    cache2 = DiskAnalysisCache(cache_dir=tmp_path)
    retrieved = get_cached_composition_edge(
        cache=cache2,
        caller_contract_hash="c_hash",
        callee_contract_hash="cal_hash",
        composition_config_hash="cfg_hash",
    )
    assert retrieved is not None
    assert retrieved.compatibility == CompatibilityState.SATISFIED


def test_composition_cache_corruption_recovery(tmp_path: Path):
    """Verify corrupted L8 entry safely returns None."""
    cache = DiskAnalysisCache(cache_dir=tmp_path)
    edge = _make_sample_edge()

    set_cached_composition_edge(cache, "c1", "c2", "cfg", edge)
    key = compute_composition_cache_key("c1", "c2", "cfg")
    artifact_path = cache._artifact_path("L8", key)
    assert artifact_path.is_file()

    artifact_path.write_text("{ corrupt json ...", encoding="utf-8")
    assert get_cached_composition_edge(cache, "c1", "c2", "cfg") is None


def test_composition_null_cache_fallback():
    """Verify NullAnalysisCache returns None for composition lookups."""
    null_cache = NullAnalysisCache()
    edge = _make_sample_edge()
    assert set_cached_composition_edge(null_cache, "c1", "c2", "cfg", edge) is True
    assert get_cached_composition_edge(null_cache, "c1", "c2", "cfg") is None
