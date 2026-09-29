"""Federated Contract Registry and cross-repository contract linker (Phase 28)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.dataflow.contracts.models import FunctionContract


class CrossRepoCallLink(BaseModel):
    """Represents a resolved call edge spanning repository boundaries."""
    model_config = ConfigDict(frozen=True)

    caller_repo_id: str
    caller_file: str
    caller_line: int
    target_repo_id: str
    target_symbol: str
    contract_hash: str
    is_pure: bool = False
    has_sanitizer_effect: bool = False
    propagates_taint: bool = False


class FederatedContractRegistry:
    """Central workspace registry linking function contracts across repository boundaries."""

    def __init__(self, workspace_id: str = "default-workspace"):
        self.workspace_id = workspace_id
        # repo_id -> { qualified_symbol -> FunctionContract }
        self._repo_contracts: dict[str, dict[str, FunctionContract]] = {}
        # package_or_module_prefix -> repo_id
        self._package_routing: dict[str, str] = {}

    def register_package_routing(self, package_prefix: str, repo_id: str) -> None:
        """Associate an import package prefix (e.g. 'auth_lib', '@org/contracts') with a repo ID."""
        clean_prefix = package_prefix.strip().rstrip(".*")
        self._package_routing[clean_prefix] = repo_id

    def publish_repository_contracts(
        self,
        repo_id: str,
        contracts: dict[str, FunctionContract],
        exported_packages: Optional[list[str]] = None,
    ) -> None:
        """Publish and index function contracts for a completed repository."""
        self._repo_contracts[repo_id] = dict(contracts)
        if exported_packages:
            for pkg in exported_packages:
                self.register_package_routing(pkg, repo_id)

    def get_repository_contracts(self, repo_id: str) -> dict[str, FunctionContract]:
        """Retrieve all registered contracts for a specific repository."""
        return dict(self._repo_contracts.get(repo_id, {}))

    def resolve_contract(
        self,
        symbol_name: str,
        module_path: Optional[str] = None,
        source_repo_hint: Optional[str] = None,
    ) -> Optional[tuple[str, FunctionContract]]:
        """Resolve a function contract across workspace repositories.

        Returns:
            Tuple of (origin_repo_id, FunctionContract) or None if unresolved.
        """
        # 1. Direct hint lookup
        if source_repo_hint and source_repo_hint in self._repo_contracts:
            contracts = self._repo_contracts[source_repo_hint]
            if symbol_name in contracts:
                return (source_repo_hint, contracts[symbol_name])
            if module_path:
                qualified = f"{module_path}.{symbol_name}"
                if qualified in contracts:
                    return (source_repo_hint, contracts[qualified])

        # 2. Package routing lookup
        if module_path:
            # Check prefixes from longest to shortest
            for prefix in sorted(self._package_routing.keys(), key=len, reverse=True):
                if module_path == prefix or module_path.startswith(f"{prefix}."):
                    target_repo = self._package_routing[prefix]
                    contracts = self._repo_contracts.get(target_repo, {})
                    qualified = f"{module_path}.{symbol_name}"
                    if qualified in contracts:
                        return (target_repo, contracts[qualified])
                    if symbol_name in contracts:
                        return (target_repo, contracts[symbol_name])

        # 3. Global scan across all registered workspace repositories
        for repo_id, contracts in self._repo_contracts.items():
            if symbol_name in contracts:
                return (repo_id, contracts[symbol_name])
            if module_path:
                qualified = f"{module_path}.{symbol_name}"
                if qualified in contracts:
                    return (repo_id, contracts[qualified])

        return None

    def compute_federated_hash(self) -> str:
        """Compute a deterministic SHA-256 canonical hash over all federated contracts."""
        canonical_state: dict[str, Any] = {
            "workspace_id": self.workspace_id,
            "routing": dict(sorted(self._package_routing.items())),
            "repositories": {},
        }
        for repo_id in sorted(self._repo_contracts.keys()):
            contracts = self._repo_contracts[repo_id]
            canonical_state["repositories"][repo_id] = {
                sym: c.compute_hash() for sym, c in sorted(contracts.items())
            }

        raw = json.dumps(canonical_state, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def save_to_directory(self, target_dir: Path) -> Path:
        """Persist federated contract catalog to disk in deterministic JSON format."""
        target_dir.mkdir(parents=True, exist_ok=True)
        meta_file = target_dir / "federated_catalog.json"
        payload = {
            "workspace_id": self.workspace_id,
            "federated_hash": self.compute_federated_hash(),
            "routing": self._package_routing,
            "repositories": {
                repo_id: {sym: c.model_dump(mode="json") for sym, c in contracts.items()}
                for repo_id, contracts in self._repo_contracts.items()
            },
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
        return meta_file

    @classmethod
    def load_from_directory(cls, target_dir: Path) -> FederatedContractRegistry:
        """Load federated contracts from a persisted catalog directory."""
        meta_file = target_dir / "federated_catalog.json"
        if not meta_file.is_file():
            raise FileNotFoundError(f"Federated contract catalog not found at {meta_file}")

        with open(meta_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        registry = cls(workspace_id=data.get("workspace_id", "default-workspace"))
        registry._package_routing = data.get("routing", {})

        for repo_id, contract_map in data.get("repositories", {}).items():
            parsed: dict[str, FunctionContract] = {}
            for sym, raw_c in contract_map.items():
                parsed[sym] = FunctionContract.model_validate(raw_c)
            registry._repo_contracts[repo_id] = parsed

        return registry
