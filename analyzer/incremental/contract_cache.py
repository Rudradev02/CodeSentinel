"""L7 per-function contract cache key derivation and lookup helpers (Phase 22).

Enables fine-grained caching of individual FunctionContract models keyed by
file path, qualified function name, context ID, contract config hash, and file content hash.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from analyzer.dataflow.contracts.models import FunctionContract
from analyzer.incremental.cache import AnalysisCache
from analyzer.incremental.contract_invalidation import compute_versioned_contract_hash

logger = logging.getLogger(__name__)

L7_LAYER = "L7"


def compute_contract_cache_key(
    file_path: str,
    qualified_name: str,
    context_id: str,
    contract_config_hash: str,
    file_content_hash: str,
) -> str:
    """Derive deterministic cache key for a per-function contract (L7)."""
    norm_path = file_path.replace("\\", "/").lstrip("./")
    payload = f"{norm_path}:{qualified_name}:{context_id}:{contract_config_hash}:{file_content_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached_contract(
    cache: AnalysisCache,
    file_path: str,
    qualified_name: str,
    context_id: str,
    contract_config_hash: str,
    file_content_hash: str,
) -> Optional[FunctionContract]:
    """Retrieve and deserialize a FunctionContract from L7 cache if valid."""
    key = compute_contract_cache_key(
        file_path=file_path,
        qualified_name=qualified_name,
        context_id=context_id,
        contract_config_hash=contract_config_hash,
        file_content_hash=file_content_hash,
    )
    data = cache.get(L7_LAYER, key)
    if not data or not isinstance(data, dict):
        return None

    try:
        contract_dict = data.get("contract")
        if not contract_dict:
            return None
        contract = FunctionContract.model_validate(contract_dict)
        # Verify versioned contract hash matches cached versioned hash
        expected_v_hash = data.get("versioned_hash")
        if expected_v_hash:
            actual_v_hash = compute_versioned_contract_hash(contract, contract_config_hash)
            if actual_v_hash != expected_v_hash:
                logger.warning("Contract versioned hash mismatch for key %s", key)
                return None
        return contract
    except Exception as exc:
        logger.warning("Failed to deserialize cached FunctionContract for key %s: %s", key, exc)
        return None


def set_cached_contract(
    cache: AnalysisCache,
    file_path: str,
    qualified_name: str,
    context_id: str,
    contract_config_hash: str,
    file_content_hash: str,
    contract: FunctionContract,
) -> bool:
    """Store a FunctionContract and its versioned hash in L7 cache."""
    key = compute_contract_cache_key(
        file_path=file_path,
        qualified_name=qualified_name,
        context_id=context_id,
        contract_config_hash=contract_config_hash,
        file_content_hash=file_content_hash,
    )
    v_hash = compute_versioned_contract_hash(contract, contract_config_hash)
    payload = {
        "contract": contract.model_dump(mode="json"),
        "versioned_hash": v_hash,
        "qualified_name": qualified_name,
        "context_id": context_id,
        "file_path": file_path.replace("\\", "/").lstrip("./"),
    }
    return cache.set(L7_LAYER, key, payload)
