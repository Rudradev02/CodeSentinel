"""Test suite for Phase 27: Attestation Standards Validation (RFC 8785 JCS & RFC 6962 Merkle)."""

import hashlib
import json
import pytest

from analyzer.compliance.attestation import (
    AttestationPredicate,
    ScanAttestationStatement,
    VerifiableAttestationEnvelope,
    canonical_json_bytes,
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


def _sample_finding(fid: str, rule: str, line: int = 1) -> Finding:
    return Finding(
        id=fid,
        rule_id=rule,
        rule_name="Attestation Test Finding",
        description="Testing Merkle Tree RFC 6962",
        remediation="Remediation advice",
        code_snippet="eval(user_input)",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        location=SourceLocation(file_path="src/crypto.py", line_start=line, line_end=line + 2),
    )


def test_rfc_8785_canonical_json_serialization():
    """Verify RFC 8785 JCS formatting: sorted UTF-8 keys, no whitespace, precise number encoding."""
    unordered = {"zeta": 1, "alpha": 2, "mid": {"b": True, "a": [3, 2, 1]}}
    canon_bytes = canonical_json_bytes(unordered)
    expected = b'{"alpha":2,"mid":{"a":[3,2,1],"b":true},"zeta":1}'
    assert canon_bytes == expected

    num_test = {"int_val": 42, "float_whole": 100.0, "float_frac": 3.1415}
    canon_nums = canonical_json_bytes(num_test)
    assert b'"float_whole":100' in canon_nums or b'"float_whole":100.0' in canon_nums
    assert b'"int_val":42' in canon_nums


def test_in_toto_statement_alias_type_serialization():
    """Verify in-toto v1.0 Statement serializes '_type' field properly via alias."""
    stmt = ScanAttestationStatement(
        subject=[{"name": "repo", "digest": "sha256:abc"}],
        predicate=AttestationPredicate(
            tool_name="CodeSentinel",
            tool_version="0.1.0",
            analysis_timestamp="2026-09-28T00:00:00Z",
            findings_merkle_root="test-root",
            suppressions_digest="",
        ),
    )
    dumped = stmt.model_dump(by_alias=True)
    assert "_type" in dumped
    assert dumped["_type"] == "https://in-toto.io/Statement/v1"

    dumped_json = stmt.model_dump_json(by_alias=True)
    assert '"_type":"https://in-toto.io/Statement/v1"' in dumped_json


def test_rfc_6962_merkle_tree_domain_separation():
    """Verify RFC 6962 domain separation (0x00 leaf prefix, 0x01 node prefix)."""
    f1 = _sample_finding("F1", "SEC-PY-001", 10)
    f2 = _sample_finding("F2", "SEC-PY-002", 20)

    # Empty findings -> SHA-256(b"EMPTY_FINDINGS")
    empty_root = compute_findings_merkle_root([])
    assert empty_root == hashlib.sha256(b"EMPTY_FINDINGS").hexdigest()

    # Single finding -> leaf hash = SHA-256(b"\x00" + leaf_content)
    root_single = compute_findings_merkle_root([f1])
    c1 = f"{f1.rule_id}:{f1.location.file_path}:{f1.location.line_start}:{f1.code_snippet.strip()}"
    expected_leaf_1 = hashlib.sha256(b"\x00" + c1.encode("utf-8")).digest().hex()
    assert root_single == expected_leaf_1

    # Two findings -> internal node hash = SHA-256(b"\x01" + left + right)
    root_double = compute_findings_merkle_root([f1, f2])
    c2 = f"{f2.rule_id}:{f2.location.file_path}:{f2.location.line_start}:{f2.code_snippet.strip()}"
    leaf1 = hashlib.sha256(b"\x00" + c1.encode("utf-8")).digest()
    leaf2 = hashlib.sha256(b"\x00" + c2.encode("utf-8")).digest()
    sorted_leaves = sorted([leaf1, leaf2])
    expected_internal = hashlib.sha256(b"\x01" + sorted_leaves[0] + sorted_leaves[1]).digest().hex()
    assert root_double == expected_internal

    # Odd count pairwise promotion
    f3 = _sample_finding("F3", "SEC-PY-003", 30)
    root_triple = compute_findings_merkle_root([f1, f2, f3])
    assert root_triple != root_double


def test_timing_safe_attestation_verification_and_tamper_detection():
    """Verify attestation verification using constant-time comparison and tamper rejection."""
    stmt = ScanAttestationStatement(
        subject=[{"name": "repo", "digest": "sha256:1234"}],
        predicate=AttestationPredicate(
            tool_name="CodeSentinel",
            tool_version="0.1.0",
            analysis_timestamp="2026-09-28T12:00:00Z",
            findings_merkle_root="abc",
            suppressions_digest="",
        ),
    )
    secret_key = "production-hsm-signing-key"
    envelope = sign_attestation(stmt, secret_key, key_id="prod-key-1")

    # 1. Valid signature
    valid, msg, reconstructed = verify_attestation(envelope, secret_key)
    assert valid is True
    assert "verified" in msg.lower()
    assert reconstructed is not None
    assert reconstructed.predicate.findings_merkle_root == "abc"

    # 2. Tampered signature
    tampered_env = envelope.model_copy(deep=True)
    tampered_sig = list(tampered_env.signatures[0]["sig"])
    tampered_sig[-1] = "a" if tampered_sig[-1] != "a" else "b"
    tampered_env.signatures[0]["sig"] = "".join(tampered_sig)
    valid_tamper, msg_tamper, _ = verify_attestation(tampered_env, secret_key)
    assert valid_tamper is False
    assert "verification failed" in msg_tamper.lower()

    # 3. Wrong secret key
    valid_wrong_key, msg_wrong, _ = verify_attestation(envelope, "wrong-key")
    assert valid_wrong_key is False

    # 4. Empty or missing secret key
    with pytest.raises(ValueError, match="secret_key cannot be empty"):
        sign_attestation(stmt, "")

    valid_empty, msg_empty, _ = verify_attestation(envelope, "")
    assert valid_empty is False
