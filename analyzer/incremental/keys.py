"""Deterministic cache key derivation across all analysis layers (Phase 21)."""

import hashlib
from pathlib import Path
from typing import Optional


def compute_repo_namespace_id(
    repo_root: Path | str,
    remote_url: Optional[str] = None,
    root_commit: Optional[str] = None,
) -> str:
    """Compute a deterministic, cross-environment repository namespace identifier."""
    if remote_url and root_commit:
        payload = f"git:{remote_url.strip()}:{root_commit.strip()}"
    else:
        # Fallback to canonical resolved path
        try:
            real_path = str(Path(repo_root).resolve()).replace("\\", "/").lower()
        except Exception:
            real_path = str(repo_root).replace("\\", "/").lower()
        payload = f"path:{real_path}"

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _hash_key(prefix: str, *parts: str) -> str:
    """Helper to compute deterministic SHA-256 digest for a cache key."""
    combined = ":".join([prefix] + [str(p) for p in parts])
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def build_l1_key(repo_namespace: str, norm_path: str) -> str:
    """L1: File fingerprint cache key."""
    return _hash_key("L1", repo_namespace, norm_path)


def build_l2_key(repo_namespace: str, file_composite_hash: str, parsing_hash: str) -> str:
    """L2: ParsedFile AST cache key."""
    return _hash_key("L2", repo_namespace, file_composite_hash, parsing_hash)


def build_l3_key(repo_namespace: str, repo_composite_hash: str, dep_config_hash: str) -> str:
    """L3: Resolved dependency graph cache key."""
    return _hash_key("L3", repo_namespace, repo_composite_hash, dep_config_hash)


def build_l4_key(repo_namespace: str, func_qn: str, body_ast_hash: str, cfg_config_hash: str) -> str:
    """L4: Function CFG cache key."""
    return _hash_key("L4", repo_namespace, func_qn, body_ast_hash, cfg_config_hash)


def build_l5_key(repo_namespace: str, func_qn: str, l4_key: str, dataflow_config_hash: str) -> str:
    """L5: Local data-flow & taint summary cache key."""
    return _hash_key("L5", repo_namespace, func_qn, l4_key, dataflow_config_hash)


def build_l6_key(repo_namespace: str, repo_composite_hash: str, callgraph_config_hash: str) -> str:
    """L6: Call graph snapshot cache key."""
    return _hash_key("L6", repo_namespace, repo_composite_hash, callgraph_config_hash)


def build_l7_key(repo_namespace: str, func_qn: str, contract_hash: str, contract_config_hash: str) -> str:
    """L7: Function summary contract cache key."""
    return _hash_key("L7", repo_namespace, func_qn, contract_hash, contract_config_hash)


def build_l8_key(
    repo_namespace: str,
    producer_contract_hash: str,
    consumer_req_hash: str,
    composition_config_hash: str,
) -> str:
    """L8: Project contract composition edge cache key."""
    return _hash_key("L8", repo_namespace, producer_contract_hash, consumer_req_hash, composition_config_hash)


def build_l9_key(repo_namespace: str, findings_hash: str, rules_config_hash: str) -> str:
    """L9: Findings and health score cache key."""
    return _hash_key("L9", repo_namespace, findings_hash, rules_config_hash)
