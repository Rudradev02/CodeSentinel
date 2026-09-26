"""L8 per-composition-edge cache key derivation and lookup helpers (Phase 22).

Enables fine-grained caching of individual ContractCompositionEdge results keyed by
caller contract versioned hash, callee contract versioned hash, composition config hash,
and optional boundary rule ID.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from analyzer.dataflow.contracts.composition import ContractCompositionEdge
from analyzer.incremental.cache import AnalysisCache

logger = logging.getLogger(__name__)

L8_LAYER = "L8"


def compute_composition_cache_key(
    caller_contract_hash: str,
    callee_contract_hash: str,
    composition_config_hash: str,
    boundary_rule_id: str = "",
) -> str:
    """Derive deterministic cache key for a contract composition edge (L8)."""
    payload = f"{caller_contract_hash}:{callee_contract_hash}:{composition_config_hash}:{boundary_rule_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached_composition_edge(
    cache: AnalysisCache,
    caller_contract_hash: str,
    callee_contract_hash: str,
    composition_config_hash: str,
    boundary_rule_id: str = "",
) -> Optional[ContractCompositionEdge]:
    """Retrieve and deserialize a ContractCompositionEdge from L8 cache if valid."""
    key = compute_composition_cache_key(
        caller_contract_hash=caller_contract_hash,
        callee_contract_hash=callee_contract_hash,
        composition_config_hash=composition_config_hash,
        boundary_rule_id=boundary_rule_id,
    )
    data = cache.get(L8_LAYER, key)
    if not data or not isinstance(data, dict):
        return None

    try:
        edge_dict = data.get("edge")
        if not edge_dict:
            return None
        return ContractCompositionEdge.model_validate(edge_dict)
    except Exception as exc:
        logger.warning("Failed to deserialize cached ContractCompositionEdge for key %s: %s", key, exc)
        return None


def set_cached_composition_edge(
    cache: AnalysisCache,
    caller_contract_hash: str,
    callee_contract_hash: str,
    composition_config_hash: str,
    edge: ContractCompositionEdge,
    boundary_rule_id: str = "",
) -> bool:
    """Store a ContractCompositionEdge in L8 cache."""
    key = compute_composition_cache_key(
        caller_contract_hash=caller_contract_hash,
        callee_contract_hash=callee_contract_hash,
        composition_config_hash=composition_config_hash,
        boundary_rule_id=boundary_rule_id,
    )
    payload = {
        "edge": edge.model_dump(mode="json"),
        "caller_contract_hash": caller_contract_hash,
        "callee_contract_hash": callee_contract_hash,
        "boundary_rule_id": boundary_rule_id,
    }
    return cache.set(L8_LAYER, key, payload)
