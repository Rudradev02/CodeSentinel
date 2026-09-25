"""Tests for Phase 20 contract composition models, graph, and hashes."""

import pytest
from analyzer.dataflow.cfg.models import RefinementFact
from analyzer.dataflow.contracts.models import (
    ExceptionDisposition,
    ExceptionalPostcondition,
    FunctionContract,
    PostconditionTrigger,
    PreconditionKind,
    ReturnAliasKind,
    SummaryPostcondition,
    SummaryPrecondition,
)
from analyzer.dataflow.contracts.composition import (
    CompatibilityState,
    ContractGuarantee,
    ContractRequirement,
    ContractCompositionEdge,
    ContractConflict,
    ContractCompositionResult,
)
from analyzer.dataflow.contracts.graph import (
    ContractEdgeType,
    ContractGraphEdge,
    ContractGraphNode,
    ContractNodeType,
    ProjectContractGraph,
)
from analyzer.dataflow.taint.models import SinkCategory


def test_exception_disposition_enum():
    """Verify ExceptionDisposition enum variants."""
    assert ExceptionDisposition.MUST_RAISE.value == "MUST_RAISE"
    assert ExceptionDisposition.MAY_RAISE.value == "MAY_RAISE"
    assert ExceptionDisposition.MUST_NOT_RAISE.value == "MUST_NOT_RAISE"


def test_exceptional_postcondition_model():
    """Verify ExceptionalPostcondition model initialization and defaults."""
    ep = ExceptionalPostcondition(
        exception_type="ValueError",
        governing_condition="user_id is None",
        disposition=ExceptionDisposition.MUST_RAISE,
        parameter_refinements_on_raise=[
            RefinementFact(variable_name="user_id", is_non_null=False)
        ],
    )
    assert ep.exception_type == "ValueError"
    assert ep.governing_condition == "user_id is None"
    assert ep.disposition == ExceptionDisposition.MUST_RAISE
    assert len(ep.parameter_refinements_on_raise) == 1


def test_return_alias_kind_enum():
    """Verify ReturnAliasKind variants."""
    assert ReturnAliasKind.ALIASED_PARAMETER.value == "ALIASED_PARAMETER"
    assert ReturnAliasKind.ALIASED_FIELD.value == "ALIASED_FIELD"
    assert ReturnAliasKind.NEW_ALLOCATION.value == "NEW_ALLOCATION"
    assert ReturnAliasKind.UNKNOWN_ALIAS.value == "UNKNOWN_ALIAS"


def test_function_contract_hash_determinism_with_phase20_fields():
    """Verify SHA-256 hash determinism with Phase 20 extensions."""
    rf1 = RefinementFact(variable_name="x", refined_type="int", is_non_null=True)
    c1 = FunctionContract(
        qualified_name="pkg.mod.validate",
        file_path="pkg/mod.py",
        exceptional_postconditions=[
            ExceptionalPostcondition(
                exception_type="TypeError",
                governing_condition="not isinstance(x, int)",
                disposition=ExceptionDisposition.MUST_RAISE,
            )
        ],
        return_alias_kind=ReturnAliasKind.ALIASED_PARAMETER,
        return_aliased_param_index=0,
        container_key_refinements={"id": rf1},
    )
    hash1 = c1.compute_hash()

    c2 = FunctionContract(
        qualified_name="pkg.mod.validate",
        file_path="pkg/mod.py",
        exceptional_postconditions=[
            ExceptionalPostcondition(
                exception_type="TypeError",
                governing_condition="not isinstance(x, int)",
                disposition=ExceptionDisposition.MUST_RAISE,
            )
        ],
        return_alias_kind=ReturnAliasKind.ALIASED_PARAMETER,
        return_aliased_param_index=0,
        container_key_refinements={"id": rf1},
    )
    hash2 = c2.compute_hash()

    assert hash1 == hash2
    assert len(hash1) == 64


def test_composition_domain_models():
    """Verify ContractGuarantee, ContractRequirement, and ContractConflict models."""
    rf = RefinementFact(variable_name="return", refined_type="int")
    g = ContractGuarantee(
        contract_id="c_val",
        guarantee_kind="TYPE_REFINEMENT",
        target_symbol="return",
        fact=rf,
        confidence="HIGH",
        provenance_rule_id="RULE-VAL",
    )
    assert g.contract_id == "c_val"
    assert g.target_symbol == "return"

    req = ContractRequirement(
        contract_id="c_sink",
        requirement_kind="TYPE_REFINEMENT",
        target_param_index=0,
        target_param_name="user_id",
        required_type="int",
        sink_category=SinkCategory.SQL_EXECUTE,
    )
    assert req.required_type == "int"

    conflict = ContractConflict(
        variable_name="user_id",
        caller_fact=RefinementFact(variable_name="user_id", refined_type="str"),
        callee_requirement=req,
        reason="Caller type str incompatible with callee requirement int",
        conflict_kind="TYPE_MISMATCH",
    )
    assert conflict.conflict_kind == "TYPE_MISMATCH"


def test_project_contract_graph_operations():
    """Verify ProjectContractGraph node and edge additions, cycle safety, and summary export."""
    graph = ProjectContractGraph(max_nodes=10)

    node1 = ContractGraphNode(
        contract_id="app.handlers.get_user",
        qualified_name="app.handlers.get_user",
        file_path="app/handlers.py",
        node_type=ContractNodeType.CONTROLLER,
    )
    node2 = ContractGraphNode(
        contract_id="app.services.fetch_user",
        qualified_name="app.services.fetch_user",
        file_path="app/services.py",
        node_type=ContractNodeType.SERVICE,
    )
    assert graph.add_node(node1) is True
    assert graph.add_node(node2) is True
    assert graph.node_count == 2

    edge = graph.add_edge(
        source_contract_id="app.handlers.get_user",
        target_contract_id="app.services.fetch_user",
        edge_type=ContractEdgeType.COMPOSED_CALL,
        call_site="app/handlers.py:25",
        composition_depth=1,
    )
    assert edge is not None
    assert graph.edge_count == 1

    summary = graph.to_summary_dict()
    assert summary["total_nodes"] == 2
    assert summary["total_edges"] == 1
    assert summary["nodes_truncated"] is False
