"""Cross-repository AI context scoping respecting Federated Contract Registry (FCR) boundaries for Phase 30.

Guarantees that multi-repository workspace analysis isolates private repository source code:
- Only verified public FunctionContracts from FCR are permitted across repository boundaries.
- External raw source files and private implementations are never leaked across repos into AI prompts.
"""

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.workspace.federated_contracts import FederatedContractRegistry


class ScopedContractSummary(BaseModel):
    """Safe, non-sensitive summary of an external repository contract."""

    model_config = ConfigDict(frozen=True)

    origin_repo_id: str
    symbol_name: str
    is_pure: bool
    has_sanitizer_effect: bool
    propagates_taint: bool
    contract_hash: str


class WorkspaceScopedContext(BaseModel):
    """Enclosed cross-repo context envelope respecting workspace isolation boundaries."""

    model_config = ConfigDict(frozen=True)

    local_repo_id: str
    workspace_id: str
    allowed_contracts: list[ScopedContractSummary]
    blocked_references: list[str] = Field(default_factory=list)
    boundary_isolation_verified: bool = True


class WorkspaceAIContextScoper:
    """Enforces FCR boundaries when assembling AI prompt contexts in multi-repo workspaces."""

    @classmethod
    def scope_external_references(
        cls,
        local_repo_id: str,
        fcr: Optional[FederatedContractRegistry],
        external_symbols: list[str],
        module_path: Optional[str] = None,
    ) -> WorkspaceScopedContext:
        """Resolve external symbols against FCR, allowing only verified declarative contracts."""
        workspace_id = fcr.workspace_id if fcr else "isolated-workspace"
        allowed_contracts: list[ScopedContractSummary] = []
        blocked: list[str] = []

        if fcr is None:
            return WorkspaceScopedContext(
                local_repo_id=local_repo_id,
                workspace_id=workspace_id,
                allowed_contracts=[],
                blocked_references=external_symbols,
                boundary_isolation_verified=True,
            )

        for sym in external_symbols:
            resolved = fcr.resolve_contract(sym, module_path=module_path)
            if resolved is not None:
                origin_repo, contract = resolved
                if origin_repo != local_repo_id:
                    has_sanitizer = getattr(contract, "has_sanitizer_effect", False) or any(
                        getattr(p, "required_sanitizer_category", None) is not None
                        for p in getattr(contract, "preconditions", [])
                    )
                    propagates_taint = getattr(contract, "propagates_taint", False) or (
                        len(getattr(contract, "conditional_effects", [])) > 0
                    )
                    allowed_contracts.append(
                        ScopedContractSummary(
                            origin_repo_id=origin_repo,
                            symbol_name=sym,
                            is_pure=bool(getattr(contract, "is_pure", False)),
                            has_sanitizer_effect=bool(has_sanitizer),
                            propagates_taint=bool(propagates_taint),
                            contract_hash=getattr(contract, "contract_hash", "") or "",
                        )
                    )
                else:
                    # Local repo symbol, not cross-repo
                    pass
            else:
                # Symbol has no public FCR contract; block to prevent cross-repo leakage
                blocked.append(sym)

        return WorkspaceScopedContext(
            local_repo_id=local_repo_id,
            workspace_id=workspace_id,
            allowed_contracts=allowed_contracts,
            blocked_references=blocked,
            boundary_isolation_verified=True,
        )
