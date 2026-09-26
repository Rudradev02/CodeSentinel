"""Incremental, dependency-aware analysis orchestration and persistent caching (Phase 21)."""

from analyzer.incremental.models import (
    ConfigFingerprint,
    FileFingerprint,
    FindingReconciliationState,
    FunctionChangeKind,
    ImpactSet,
    IncrementalStats,
    InvalidationReason,
)
from analyzer.incremental.contract_cache import (
    compute_contract_cache_key,
    get_cached_contract,
    set_cached_contract,
)
from analyzer.incremental.composition_cache import (
    compute_composition_cache_key,
    get_cached_composition_edge,
    set_cached_composition_edge,
)

__all__ = [
    "ConfigFingerprint",
    "FileFingerprint",
    "FindingReconciliationState",
    "FunctionChangeKind",
    "ImpactSet",
    "IncrementalStats",
    "InvalidationReason",
    "compute_contract_cache_key",
    "get_cached_contract",
    "set_cached_contract",
    "compute_composition_cache_key",
    "get_cached_composition_edge",
    "set_cached_composition_edge",
]
