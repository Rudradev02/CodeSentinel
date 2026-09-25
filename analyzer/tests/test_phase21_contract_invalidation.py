"""Unit tests for Phase 21 contract-aware and security-boundary invalidation."""

from analyzer.dataflow.cfg.models import RefinementFact
from analyzer.dataflow.contracts.models import (
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.incremental.contract_invalidation import (
    compute_versioned_contract_hash,
    get_affected_security_boundary_rules,
    should_prune_caller_reanalysis,
)


class TestContractVersioningAndPruning:
    """Verifies that callers are safely pruned only when versioned contract hashes match."""

    def test_versioned_contract_hash_deterministic(self):
        c1 = FunctionContract(qualified_name="auth.validate_id", file_path="auth/validate.py")
        h1 = compute_versioned_contract_hash(c1, contract_config_hash="cfg123")
        h2 = compute_versioned_contract_hash(c1, contract_config_hash="cfg123")
        assert h1 == h2
        assert len(h1) == 64

    def test_versioned_contract_hash_config_dependency(self):
        c1 = FunctionContract(qualified_name="auth.validate_id", file_path="auth/validate.py")
        h1 = compute_versioned_contract_hash(c1, contract_config_hash="cfg_a")
        h2 = compute_versioned_contract_hash(c1, contract_config_hash="cfg_b")
        assert h1 != h2

    def test_prune_caller_reanalysis_identical_contract(self):
        c_old = FunctionContract(
            qualified_name="auth.validate_id",
            file_path="auth/validate.py",
            preconditions=[
                SummaryPrecondition(
                    target_param_index=0,
                    target_param_name="x",
                    kind=PreconditionKind.TYPE_REFINEMENT,
                )
            ],
        )
        c_new = FunctionContract(
            qualified_name="auth.validate_id",
            file_path="auth/validate.py",
            preconditions=[
                SummaryPrecondition(
                    target_param_index=0,
                    target_param_name="x",
                    kind=PreconditionKind.TYPE_REFINEMENT,
                )
            ],
        )
        assert should_prune_caller_reanalysis(c_old, c_new, "cfg_hash") is True

    def test_do_not_prune_when_contract_modified(self):
        c_old = FunctionContract(
            qualified_name="auth.validate_id",
            file_path="auth/validate.py",
            preconditions=[
                SummaryPrecondition(
                    target_param_index=0,
                    target_param_name="x",
                    kind=PreconditionKind.TYPE_REFINEMENT,
                )
            ],
        )
        # Contract modified: postcondition added
        c_new = FunctionContract(
            qualified_name="auth.validate_id",
            file_path="auth/validate.py",
            preconditions=[
                SummaryPrecondition(
                    target_param_index=0,
                    target_param_name="x",
                    kind=PreconditionKind.TYPE_REFINEMENT,
                )
            ],
            postconditions=[
                SummaryPostcondition(
                    trigger=PostconditionTrigger.RETURN_EQUALS_TRUE,
                    target_param_name="x",
                    produced_refinement=RefinementFact(
                        variable_name="x",
                        refined_type="int",
                    ),
                )
            ],
        )
        assert should_prune_caller_reanalysis(c_old, c_new, "cfg_hash") is False

    def test_do_not_prune_when_contract_none(self):
        c = FunctionContract(qualified_name="auth.validate_id", file_path="auth/validate.py")
        assert should_prune_caller_reanalysis(None, c, "cfg") is False
        assert should_prune_caller_reanalysis(c, None, "cfg") is False


class TestSecurityBoundaryRuleIsolation:
    """Verifies rule-specific isolation of security boundary invalidations."""

    def test_dom_injection_rule_isolation(self):
        affected = get_affected_security_boundary_rules(SinkCategory.DOM_INJECTION)
        assert "SEC-JS-009" in affected
        # Must NOT invalidate SQL rule SEC-PY-011 or Command rule SEC-PY-012
        assert "SEC-PY-011" not in affected

    def test_sql_execute_rule_isolation(self):
        affected = get_affected_security_boundary_rules(SinkCategory.SQL_EXECUTE)
        assert "SEC-PY-011" in affected
        assert "SEC-JS-010" not in affected
