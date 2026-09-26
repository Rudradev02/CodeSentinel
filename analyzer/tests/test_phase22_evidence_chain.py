"""Unit tests for Phase 22 SecurityEvidenceChain models and integration."""

import json
from analyzer.models.evidence import (
    BoundaryEvaluationEvidence,
    ContractEvaluationEvidence,
    PropagationStep,
    SanitizerEvidence,
    SecurityEvidenceChain,
    TaintSinkEvidence,
    TaintSourceEvidence,
)
from analyzer.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)


def test_evidence_submodels_instantiation():
    """Verify all evidence submodels can be constructed with expected fields."""
    source = TaintSourceEvidence(
        source_category="HTTP_PARAM",
        file_path="app/views.py",
        line=12,
        column=4,
        expression="request.GET.get('id')",
        framework="Django",
    )
    assert source.source_category == "HTTP_PARAM"
    assert source.file_path == "app/views.py"

    step = PropagationStep(
        step_index=0,
        file_path="app/views.py",
        line=15,
        column=8,
        operation="ASSIGNMENT",
        from_symbol="user_id",
        to_symbol="query_param",
        taint_state="TAINTED",
    )
    assert step.step_index == 0
    assert step.operation == "ASSIGNMENT"

    sanitizer = SanitizerEvidence(
        sanitizer_id="shlex.quote",
        effective_categories=["COMMAND_EXECUTE"],
        file_path="app/utils.py",
        line=45,
        expression="shlex.quote(cmd)",
        is_category_compatible=True,
    )
    assert sanitizer.sanitizer_id == "shlex.quote"
    assert sanitizer.is_category_compatible is True

    sink = TaintSinkEvidence(
        sink_category="COMMAND_EXECUTE",
        rule_id="SEC-PY-002",
        file_path="app/tasks.py",
        line=88,
        column=12,
        callee_name="subprocess.Popen",
        vulnerable_arg_index=0,
        parameter_binding_available=False,
    )
    assert sink.sink_category == "COMMAND_EXECUTE"
    assert sink.callee_name == "subprocess.Popen"

    contract = ContractEvaluationEvidence(
        call_site_file="app/services.py",
        call_site_line=24,
        caller_qn="services.run_task",
        callee_qn="tasks.execute",
        contract_id="tasks.execute:ROOT",
        evaluation_result="SATISFIED",
        precondition_kind="TAINT_FREE",
        details="Precondition satisfied by upstream sanitizer",
    )
    assert contract.evaluation_result == "SATISFIED"

    boundary = BoundaryEvaluationEvidence(
        rule_id="SEC-PY-002",
        sink_category="COMMAND_EXECUTE",
        sanitizer_category="SQL_INJECTION",
        compatibility_state="VIOLATED",
        accepted_sanitizers=["shlex_quote", "subprocess_list"],
        incompatible_sanitizers=["sql_escape"],
        details="SQL sanitizer does not protect against command execution",
    )
    assert boundary.compatibility_state == "VIOLATED"


def test_security_evidence_chain_hash_determinism():
    """Verify SecurityEvidenceChain computes deterministic hashes."""
    chain1 = SecurityEvidenceChain(
        taint_source=TaintSourceEvidence(
            source_category="HTTP_PARAM",
            file_path="app/views.py",
            line=10,
            column=2,
            expression="request.args['name']",
        ),
        propagation_chain=[
            PropagationStep(
                step_index=0,
                file_path="app/views.py",
                line=12,
                operation="ASSIGNMENT",
                from_symbol="name",
                to_symbol="query",
            )
        ],
        taint_sink=TaintSinkEvidence(
            sink_category="SQL_EXECUTE",
            rule_id="SEC-PY-001",
            file_path="app/db.py",
            line=50,
            callee_name="cursor.execute",
        ),
        chain_confidence="HIGH",
        chain_depth=1,
    )

    # Identical content
    chain2 = SecurityEvidenceChain(
        taint_source=TaintSourceEvidence(
            source_category="HTTP_PARAM",
            file_path="app/views.py",
            line=10,
            column=2,
            expression="request.args['name']",
        ),
        propagation_chain=[
            PropagationStep(
                step_index=0,
                file_path="app/views.py",
                line=12,
                operation="ASSIGNMENT",
                from_symbol="name",
                to_symbol="query",
            )
        ],
        taint_sink=TaintSinkEvidence(
            sink_category="SQL_EXECUTE",
            rule_id="SEC-PY-001",
            file_path="app/db.py",
            line=50,
            callee_name="cursor.execute",
        ),
        chain_confidence="HIGH",
        chain_depth=1,
    )

    hash1 = chain1.compute_chain_hash()
    hash2 = chain2.compute_chain_hash()

    assert hash1 == hash2
    assert len(hash1) == 64
    assert chain1.chain_hash == hash1


def test_security_evidence_chain_hash_invalidation_on_mutation():
    """Verify hash changes if any step or contract evaluation changes."""
    chain = SecurityEvidenceChain(
        taint_source=TaintSourceEvidence(
            source_category="HTTP_PARAM",
            file_path="app/views.py",
            line=10,
            column=2,
            expression="request.args['name']",
        ),
        taint_sink=TaintSinkEvidence(
            sink_category="SQL_EXECUTE",
            rule_id="SEC-PY-001",
            file_path="app/db.py",
            line=50,
            callee_name="cursor.execute",
        ),
    )
    original_hash = chain.compute_chain_hash()

    # Mutate chain with contract evaluation
    chain.contract_evaluations.append(
        ContractEvaluationEvidence(
            call_site_file="app/views.py",
            call_site_line=15,
            caller_qn="views.index",
            callee_qn="db.query",
            contract_id="c1",
            evaluation_result="VIOLATED",
        )
    )
    mutated_hash = chain.compute_chain_hash()
    assert mutated_hash != original_hash


def test_finding_evidence_embedding_compatibility():
    """Verify SecurityEvidenceChain can be stored in Finding.evidence['security_chain'] without altering finding identity."""
    loc = SourceLocation(file_path="app/views.py", line_start=20)
    finding1 = Finding(
        rule_id="SEC-PY-001",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        title="SQL Injection",
        description="User input flows to cursor.execute",
        location=loc,
    )
    original_id = finding1.id

    # Construct and serialize chain
    chain = SecurityEvidenceChain(
        taint_source=TaintSourceEvidence(
            source_category="HTTP_PARAM",
            file_path="app/views.py",
            line=20,
            expression="request.GET['id']",
        ),
        taint_sink=TaintSinkEvidence(
            sink_category="SQL_EXECUTE",
            rule_id="SEC-PY-001",
            file_path="app/views.py",
            line=25,
            callee_name="cursor.execute",
        ),
    )
    chain.compute_chain_hash()

    finding2 = Finding(
        rule_id="SEC-PY-001",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        title="SQL Injection",
        description="User input flows to cursor.execute",
        location=loc,
        evidence={"security_chain": chain.model_dump(mode="json")},
    )

    # Invariant: Finding ID must be identical regardless of evidence payload
    assert finding2.id == original_id
    assert "security_chain" in finding2.evidence
    reconstructed = SecurityEvidenceChain.model_validate(finding2.evidence["security_chain"])
    assert reconstructed.taint_source.source_category == "HTTP_PARAM"
    assert reconstructed.taint_sink.callee_name == "cursor.execute"
