"""Unit tests for Phase 24 Scoped Incremental Fingerprinting and Equivalence Verification."""

import pytest
from analyzer.config.settings import AnalysisConfig
from analyzer.incremental.config_fingerprint import compute_scoped_config_fingerprint
from analyzer.incremental.equivalence import EquivalenceChecker, EquivalenceResult, EquivalenceDiscrepancyKind
from analyzer.models.results import AnalysisResult, RepositoryInfo
from analyzer.models.findings import Finding, FindingCategory, FindingSeverity, EvidenceType, SourceLocation


def test_scoped_fingerprint_contains_policy_and_framework_hashes():
    """Verify compute_scoped_config_fingerprint produces distinct policy and framework hashes."""
    cfg = AnalysisConfig()
    fp = compute_scoped_config_fingerprint(cfg)
    assert len(fp.policy_hash) == 64
    assert len(fp.framework_model_hash) == 64


def test_policy_config_change_invalidates_policy_hash_only():
    """Verify changing policy parameters alters policy_hash while parsing_hash remains unchanged."""
    cfg1 = AnalysisConfig(policy_mode="ENFORCE")
    cfg2 = AnalysisConfig(policy_mode="ADVISORY")

    fp1 = compute_scoped_config_fingerprint(cfg1)
    fp2 = compute_scoped_config_fingerprint(cfg2)

    assert fp1.policy_hash != fp2.policy_hash
    assert fp1.parsing_hash == fp2.parsing_hash
    assert fp1.dependency_hash == fp2.dependency_hash
    assert fp1.cfg_dataflow_hash == fp2.cfg_dataflow_hash


def test_equivalence_checker_with_policy_verification():
    """Verify EquivalenceChecker catches discrepancies in proof obligations."""
    loc = SourceLocation(file_path="src/app.py", line_start=10)
    f1 = Finding(
        id="f0000000-0000-0000-0000-000000000001",
        rule_id="SEC-PY-001",
        rule_name="SQL Injection",
        message="SQL injection",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        confidence=FindingSeverity.HIGH,
        evidence_type=EvidenceType.DETERMINISTIC,
        description="SQL injection",
        remediation="Parametrize",
        location=loc,
        code_snippet="cursor.execute(q)",
        evidence={
            "policy_evaluation": {"policy_id": "POL-SQL-01", "evaluation_result": "VIOLATED"},
            "proof_obligations": [{"obligation_id": "OBL_1", "state": "PROVEN_VIOLATION"}],
        },
    )

    f2_diff_obl = Finding(
        id="f0000000-0000-0000-0000-000000000001",
        rule_id="SEC-PY-001",
        rule_name="SQL Injection",
        message="SQL injection",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        confidence=FindingSeverity.HIGH,
        evidence_type=EvidenceType.DETERMINISTIC,
        description="SQL injection",
        remediation="Parametrize",
        location=loc,
        code_snippet="cursor.execute(q)",
        evidence={
            "policy_evaluation": {"policy_id": "POL-SQL-01", "evaluation_result": "VIOLATED"},
            "proof_obligations": [{"obligation_id": "OBL_1", "state": "UNKNOWN"}],
        },
    )

    repo_info = RepositoryInfo(name="repo", local_path="/tmp")
    res_full = AnalysisResult(repository=repo_info, security_findings=[f1], architecture_findings=[])
    res_inc = AnalysisResult(repository=repo_info, security_findings=[f2_diff_obl], architecture_findings=[])

    equiv = EquivalenceChecker.compare(res_full, res_inc, verify_policies=True)
    assert equiv.is_equivalent is False
    assert equiv.policies_matched is False
    assert any("POLICY_MISMATCH" in d for d in equiv.discrepancies)
