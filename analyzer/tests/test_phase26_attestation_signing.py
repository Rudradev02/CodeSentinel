"""Tests for cryptographic scan attestation, Merkle roots, and DSSE envelope verification."""

import pytest
from analyzer.compliance.attestation import (
    AttestationPredicate,
    ScanAttestationStatement,
    compute_findings_merkle_root,
    sign_attestation,
    verify_attestation,
)
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)


def _make_finding(rule_id: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/test.py", line_start=line),
        code_snippet="eval(x)",
        description="Sample finding",
        remediation="Sample remediation",
    )


def test_merkle_root_determinism_and_order_invariance():
    """Verify Merkle root is deterministic regardless of the order findings are supplied."""
    f1 = _make_finding("SEC-PY-001", 10)
    f2 = _make_finding("SEC-PY-003", 20)
    f3 = _make_finding("SEC-PY-005", 30)

    root1 = compute_findings_merkle_root([f1, f2, f3])
    root2 = compute_findings_merkle_root([f3, f1, f2])
    root3 = compute_findings_merkle_root([f2, f3, f1])

    assert len(root1) == 64
    assert root1 == root2 == root3


def test_merkle_root_changes_on_finding_modification():
    """Verify any change in a finding alters the computed Merkle root."""
    f1 = _make_finding("SEC-PY-001", 10)
    f2 = _make_finding("SEC-PY-003", 20)
    root_orig = compute_findings_merkle_root([f1, f2])

    f2_modified = _make_finding("SEC-PY-003", 21)
    root_mod = compute_findings_merkle_root([f1, f2_modified])

    assert root_orig != root_mod


def test_merkle_root_empty_findings():
    """Verify empty finding list produces a deterministic 64-char hex digest."""
    root = compute_findings_merkle_root([])
    assert len(root) == 64


def test_attestation_signing_and_verification_success():
    """Verify signing with correct secret key verifies successfully."""
    predicate = AttestationPredicate(
        tool_name="CodeSentinel",
        tool_version="0.1.0",
        analysis_timestamp="2026-09-28T12:00:00Z",
        config_fingerprint="abc123config",
        findings_merkle_root="f00df00d" * 8,
        suppressions_digest="supp123",
        compliance_scores={"PCI_DSS_V4_0": 95.0},
        gate_verdict="PASS",
    )
    stmt = ScanAttestationStatement(
        subject=[{"name": "test-repo", "digest": "deadbeef" * 8}],
        predicate=predicate,
    )
    secret = "super-secret-enterprise-key-42"
    envelope = sign_attestation(stmt, secret, key_id="prod-key-1")

    assert envelope.payloadType == "application/vnd.in-toto+json"
    assert len(envelope.signatures) == 1
    assert envelope.signatures[0]["keyid"] == "prod-key-1"

    is_valid, msg, verified_stmt = verify_attestation(envelope, secret)
    assert is_valid is True
    assert "verified successfully" in msg
    assert verified_stmt is not None
    assert verified_stmt.predicate.config_fingerprint == "abc123config"
    assert verified_stmt.predicate.gate_verdict == "PASS"


def test_attestation_verification_fails_with_wrong_key():
    """Verify verification fails when signed with key A and verified with key B."""
    predicate = AttestationPredicate(
        tool_name="CodeSentinel",
        tool_version="0.1.0",
        analysis_timestamp="2026-09-28T12:00:00Z",
        config_fingerprint="abc",
        findings_merkle_root="def",
        suppressions_digest="",
    )
    stmt = ScanAttestationStatement(subject=[], predicate=predicate)
    envelope = sign_attestation(stmt, "correct-key")

    is_valid, msg, stmt_res = verify_attestation(envelope, "wrong-key")
    assert is_valid is False
    assert "verification failed" in msg
    assert stmt_res is None


def test_attestation_verification_fails_on_tampered_payload():
    """Verify tampered payload is immediately detected and rejected."""
    predicate = AttestationPredicate(
        tool_name="CodeSentinel",
        tool_version="0.1.0",
        analysis_timestamp="2026-09-28T12:00:00Z",
        config_fingerprint="abc",
        findings_merkle_root="def",
        suppressions_digest="",
    )
    stmt = ScanAttestationStatement(subject=[], predicate=predicate)
    envelope = sign_attestation(stmt, "key-123")

    # Tamper payload
    tampered_envelope = envelope.model_copy(update={"payload": envelope.payload[:-4] + "AAAA"})
    is_valid, msg, stmt_res = verify_attestation(tampered_envelope, "key-123")
    assert is_valid is False
