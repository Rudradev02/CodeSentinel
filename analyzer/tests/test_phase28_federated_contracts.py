"""Unit tests for Phase 28 Federated Contract Registry and cross-repo contract resolution."""

import tempfile
from pathlib import Path
import pytest

from analyzer.dataflow.contracts.models import (
    ConditionalTaintEffect,
    FunctionContract,
    PreconditionKind,
    ReturnAliasKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.workspace.federated_contracts import FederatedContractRegistry


@pytest.fixture
def sample_contracts() -> dict[str, FunctionContract]:
    contract_clean = FunctionContract(
        qualified_name="auth.sanitize_token",
        file_path="src/auth/tokens.py",
        is_pure=True,
        conditional_effects=[
            ConditionalTaintEffect(
                parameter_index=0,
                sanitizes_category="COMMAND_INJECTION",
                description="Sanitizes shell command injection tokens",
            )
        ],
    )
    contract_db = FunctionContract(
        qualified_name="db.query_user",
        file_path="src/db/repo.py",
        is_pure=False,
        preconditions=[
            SummaryPrecondition(
                target_param_index=0,
                target_param_name="user_id",
                kind=PreconditionKind.TYPE_REFINEMENT,
                required_type="int",
                raw_condition="isinstance(user_id, int)",
            )
        ],
    )
    return {
        "sanitize_token": contract_clean,
        "query_user": contract_db,
    }


class TestFederatedContractRegistry:
    """Tests for cross-repository contract storage, resolution, and caching."""

    def test_publish_and_resolve_via_package_routing(self, sample_contracts):
        registry = FederatedContractRegistry("workspace-alpha")
        registry.publish_repository_contracts(
            repo_id="auth-repo",
            contracts={"auth.sanitize_token": sample_contracts["sanitize_token"]},
            exported_packages=["auth"],
        )

        # Resolve by package routing
        result = registry.resolve_contract(symbol_name="sanitize_token", module_path="auth")
        assert result is not None
        repo_id, contract = result
        assert repo_id == "auth-repo"
        assert contract.qualified_name == "auth.sanitize_token"
        assert contract.is_pure is True

    def test_resolve_via_direct_repo_hint(self, sample_contracts):
        registry = FederatedContractRegistry("workspace-alpha")
        registry.publish_repository_contracts(
            repo_id="db-repo",
            contracts={"query_user": sample_contracts["query_user"]},
        )

        result = registry.resolve_contract(
            symbol_name="query_user",
            source_repo_hint="db-repo",
        )
        assert result is not None
        repo_id, contract = result
        assert repo_id == "db-repo"
        assert contract.qualified_name == "db.query_user"
        assert len(contract.preconditions) == 1

    def test_resolve_unregistered_returns_none(self):
        registry = FederatedContractRegistry("workspace-alpha")
        result = registry.resolve_contract(symbol_name="non_existent_func")
        assert result is None

    def test_federated_hash_determinism(self, sample_contracts):
        reg1 = FederatedContractRegistry("workspace-1")
        reg1.publish_repository_contracts("repo-a", {"auth.sanitize": sample_contracts["sanitize_token"]}, ["auth"])

        reg2 = FederatedContractRegistry("workspace-1")
        reg2.publish_repository_contracts("repo-a", {"auth.sanitize": sample_contracts["sanitize_token"]}, ["auth"])

        assert reg1.compute_federated_hash() == reg2.compute_federated_hash()
        assert len(reg1.compute_federated_hash()) == 64

    def test_save_and_load_roundtrip(self, sample_contracts):
        with tempfile.TemporaryDirectory() as tmp_dir:
            save_path = Path(tmp_dir)
            orig_reg = FederatedContractRegistry("workspace-save-test")
            orig_reg.publish_repository_contracts(
                repo_id="auth-repo",
                contracts={"auth.sanitize_token": sample_contracts["sanitize_token"]},
                exported_packages=["auth"],
            )
            orig_reg.publish_repository_contracts(
                repo_id="db-repo",
                contracts={"db.query_user": sample_contracts["query_user"]},
                exported_packages=["db"],
            )

            meta_file = orig_reg.save_to_directory(save_path)
            assert meta_file.is_file()

            loaded_reg = FederatedContractRegistry.load_from_directory(save_path)
            assert loaded_reg.workspace_id == "workspace-save-test"

            res1 = loaded_reg.resolve_contract("sanitize_token", module_path="auth")
            assert res1 is not None
            assert res1[0] == "auth-repo"

            res2 = loaded_reg.resolve_contract("query_user", module_path="db")
            assert res2 is not None
            assert res2[0] == "db-repo"
