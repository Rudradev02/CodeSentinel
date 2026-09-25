"""Contract-aware and security-boundary invalidation engine (Phase 21)."""

import hashlib
import json
from typing import Optional

from analyzer.dataflow.contracts.models import FunctionContract
from analyzer.dataflow.contracts.security_boundary import SECURITY_BOUNDARY_SPECS
from analyzer.dataflow.taint.models import SinkCategory

CONTRACT_SCHEMA_VERSION = "1.0.0"
ANALYZER_VERSION = "0.1.0"


def compute_versioned_contract_hash(
    contract: FunctionContract,
    contract_config_hash: str,
    contract_schema_version: str = CONTRACT_SCHEMA_VERSION,
    analyzer_version: str = ANALYZER_VERSION,
) -> str:
    """Compute canonical versioned SHA-256 hash for a function contract.
    
    Incorporate:
    - Base contract content hash
    - Contract schema version
    - Active contract configuration hash
    - Analyzer version
    """
    base_hash = contract.compute_hash()
    payload = f"{base_hash}:{contract_schema_version}:{contract_config_hash}:{analyzer_version}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def should_prune_caller_reanalysis(
    old_contract: Optional[FunctionContract],
    new_contract: Optional[FunctionContract],
    contract_config_hash: str,
) -> bool:
    """Determine whether callers of a modified function can safely skip re-analysis.
    
    A caller may reuse a cached contract composition result after a callee body change
    only if the callee contract is proven equivalent under the active versioned hash.
    """
    if old_contract is None or new_contract is None:
        return False

    old_v_hash = compute_versioned_contract_hash(old_contract, contract_config_hash)
    new_v_hash = compute_versioned_contract_hash(new_contract, contract_config_hash)

    return old_v_hash == new_v_hash


def get_affected_security_boundary_rules(
    modified_sanitizer_category: SinkCategory,
) -> set[str]:
    """Identify which rule IDs are affected by a change to a sanitizer or sink behavior.
    
    Guarantees:
    - Rule-specific isolation: Changing an HTML escaping sanitizer affects DOM XSS rules
      (e.g. SEC-JS-009) whose sinks accept DOM_INJECTION, but does not invalidate SQL execution (SEC-PY-011)
      or Command execution (SEC-PY-012).
    """
    affected_rules: set[str] = set()

    for rule_id, spec in SECURITY_BOUNDARY_SPECS.items():
        if (
            modified_sanitizer_category in spec.accepted_sanitizers
            or modified_sanitizer_category == spec.sink_category
        ):
            affected_rules.add(rule_id)

    return affected_rules
