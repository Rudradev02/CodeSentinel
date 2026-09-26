"""Unit tests for Phase 22 L7 per-function contract cache."""

from pathlib import Path
import json

from analyzer.dataflow.contracts.models import FunctionContract, PreconditionKind, SummaryPrecondition
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache, NullAnalysisCache
from analyzer.incremental.contract_cache import (
    compute_contract_cache_key,
    get_cached_contract,
    set_cached_contract,
)


def test_compute_contract_cache_key_determinism():
    """Verify L7 contract cache key computation is deterministic."""
    k1 = compute_contract_cache_key(
        file_path="app/views.py",
        qualified_name="views.handle_request",
        context_id="ROOT",
        contract_config_hash="cfg_hash_1",
        file_content_hash="content_hash_1",
    )
    k2 = compute_contract_cache_key(
        file_path="app/views.py",
        qualified_name="views.handle_request",
        context_id="ROOT",
        contract_config_hash="cfg_hash_1",
        file_content_hash="content_hash_1",
    )
    assert k1 == k2
    assert len(k1) == 64


def test_compute_contract_cache_key_sensitivity():
    """Verify cache key changes when any key component changes."""
    base_key = compute_contract_cache_key(
        file_path="app/views.py",
        qualified_name="views.handle_request",
        context_id="ROOT",
        contract_config_hash="cfg_hash_1",
        file_content_hash="content_hash_1",
    )

    # Different path
    k_path = compute_contract_cache_key("app/api.py", "views.handle_request", "ROOT", "cfg_hash_1", "content_hash_1")
    assert k_path != base_key

    # Different function
    k_fn = compute_contract_cache_key("app/views.py", "views.other_fn", "ROOT", "cfg_hash_1", "content_hash_1")
    assert k_fn != base_key

    # Different context
    k_ctx = compute_contract_cache_key("app/views.py", "views.handle_request", "CALL_SITE_1", "cfg_hash_1", "content_hash_1")
    assert k_ctx != base_key

    # Different contract config
    k_cfg = compute_contract_cache_key("app/views.py", "views.handle_request", "ROOT", "cfg_hash_2", "content_hash_1")
    assert k_cfg != base_key

    # Different content hash
    k_content = compute_contract_cache_key("app/views.py", "views.handle_request", "ROOT", "cfg_hash_1", "content_hash_2")
    assert k_content != base_key


def test_set_and_get_cached_contract_in_memory():
    """Verify storing and retrieving a FunctionContract in InMemoryAnalysisCache."""
    cache = InMemoryAnalysisCache()
    contract = FunctionContract(
        qualified_name="auth.validate_token",
        file_path="auth/token.py",
        preconditions=[
            SummaryPrecondition(
                target_param_index=0,
                target_param_name="token",
                kind=PreconditionKind.NULLITY_REFINEMENT,
            )
        ],
    )

    ok = set_cached_contract(
        cache=cache,
        file_path="auth/token.py",
        qualified_name="auth.validate_token",
        context_id="ROOT",
        contract_config_hash="cfg_hash_v1",
        file_content_hash="content_hash_v1",
        contract=contract,
    )
    assert ok is True

    cached = get_cached_contract(
        cache=cache,
        file_path="auth/token.py",
        qualified_name="auth.validate_token",
        context_id="ROOT",
        contract_config_hash="cfg_hash_v1",
        file_content_hash="content_hash_v1",
    )
    assert cached is not None
    assert cached.qualified_name == "auth.validate_token"
    assert len(cached.preconditions) == 1
    assert cached.preconditions[0].kind == PreconditionKind.NULLITY_REFINEMENT


def test_cached_contract_miss_on_invalidation():
    """Verify cache miss when file content or config hash changes."""
    cache = InMemoryAnalysisCache()
    contract = FunctionContract(qualified_name="auth.validate", file_path="auth/val.py")
    set_cached_contract(
        cache=cache,
        file_path="auth/val.py",
        qualified_name="auth.validate",
        context_id="ROOT",
        contract_config_hash="cfg1",
        file_content_hash="content1",
        contract=contract,
    )

    # Miss on content change
    assert get_cached_contract(cache, "auth/val.py", "auth.validate", "ROOT", "cfg1", "content2") is None

    # Miss on config change
    assert get_cached_contract(cache, "auth/val.py", "auth.validate", "ROOT", "cfg2", "content1") is None


def test_cached_contract_disk_persistence(tmp_path: Path):
    """Verify L7 contract storage persists across DiskAnalysisCache instances."""
    cache1 = DiskAnalysisCache(cache_dir=tmp_path)
    contract = FunctionContract(qualified_name="db.execute", file_path="db/query.py")

    set_cached_contract(
        cache=cache1,
        file_path="db/query.py",
        qualified_name="db.execute",
        context_id="ROOT",
        contract_config_hash="cfg_1",
        file_content_hash="cnt_1",
        contract=contract,
    )

    # Reopen fresh disk cache
    cache2 = DiskAnalysisCache(cache_dir=tmp_path)
    retrieved = get_cached_contract(
        cache=cache2,
        file_path="db/query.py",
        qualified_name="db.execute",
        context_id="ROOT",
        contract_config_hash="cfg_1",
        file_content_hash="cnt_1",
    )
    assert retrieved is not None
    assert retrieved.qualified_name == "db.execute"


def test_cached_contract_corruption_recovery(tmp_path: Path):
    """Verify corrupted contract entry on disk safely falls back to None."""
    cache = DiskAnalysisCache(cache_dir=tmp_path)
    contract = FunctionContract(qualified_name="test.fn", file_path="test/fn.py")

    set_cached_contract(cache, "test/fn.py", "test.fn", "ROOT", "cfg1", "cnt1", contract)
    key = compute_contract_cache_key("test/fn.py", "test.fn", "ROOT", "cfg1", "cnt1")
    artifact_path = cache._artifact_path("L7", key)
    assert artifact_path.is_file()

    # Corrupt the JSON payload inside the file
    artifact_path.write_text("{ corrupt json ...", encoding="utf-8")

    result = get_cached_contract(cache, "test/fn.py", "test.fn", "ROOT", "cfg1", "cnt1")
    assert result is None


def test_null_cache_behavior():
    """Verify NullAnalysisCache gracefully returns None without error."""
    null_cache = NullAnalysisCache()
    contract = FunctionContract(qualified_name="auth.check", file_path="auth/check.py")
    assert set_cached_contract(null_cache, "auth/check.py", "auth.check", "ROOT", "c", "h", contract) is True
    assert get_cached_contract(null_cache, "auth/check.py", "auth.check", "ROOT", "c", "h") is None


def test_path_normalization_equivalence():
    """Verify Windows backslashes and relative paths normalize to matching keys."""
    k_win = compute_contract_cache_key("app\\views\\auth.py", "auth.login", "ROOT", "c", "h")
    k_nix = compute_contract_cache_key("app/views/auth.py", "auth.login", "ROOT", "c", "h")
    k_rel = compute_contract_cache_key("./app/views/auth.py", "auth.login", "ROOT", "c", "h")
    assert k_win == k_nix == k_rel
