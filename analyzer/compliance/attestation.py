"""Cryptographically verifiable scan attestations (in-toto & DSSE) for CodeSentinel (Phase 26)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.models.findings import Finding


class AttestationPredicate(BaseModel):
    """Predicate payload capturing the deterministic execution state of an analysis run."""
    model_config = ConfigDict(frozen=True)

    tool_name: str = "CodeSentinel"
    tool_version: str = "0.1.0"
    analysis_timestamp: str               # ISO-8601 UTC
    git_commit_hash: Optional[str] = None
    git_tree_hash: Optional[str] = None
    config_fingerprint: str              # ConfigFingerprint.global_hash or config digest
    findings_merkle_root: str            # Merkle root of sorted finding hashes
    suppressions_digest: str             # SHA-256 of active suppressions
    compliance_scores: dict[str, float] = Field(default_factory=dict)
    gate_verdict: str = "PASS"           # "PASS", "FAIL", "WARN"


class ScanAttestationStatement(BaseModel):
    """in-toto v1.0 Statement envelope."""
    model_config = ConfigDict(frozen=True)

    _type: str = "https://in-toto.io/Statement/v1"
    subject: list[dict[str, str]] = Field(default_factory=list)
    predicateType: str = "https://codesentinel.dev/attestation/compliance/v1"
    predicate: AttestationPredicate


class VerifiableAttestationEnvelope(BaseModel):
    """DSSE (Dead Simple Signing Envelope) formatted cryptographic attestation."""
    payload: str                         # Base64-encoded canonical JSON of ScanAttestationStatement
    payloadType: str = "application/vnd.in-toto+json"
    signatures: list[dict[str, str]] = Field(default_factory=list)


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize object to deterministic, canonical RFC 8785 JSON bytes."""
    if isinstance(data, BaseModel):
        data_dict = data.model_dump(exclude_none=True)
    elif isinstance(data, dict):
        data_dict = data
    else:
        raise ValueError(f"Cannot serialize type {type(data)} to canonical JSON")

    return json.dumps(data_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_findings_merkle_root(findings: list[Finding]) -> str:
    """Compute a deterministic SHA-256 binary Merkle tree root over all finding fingerprints."""
    if not findings:
        return hashlib.sha256(b"EMPTY_FINDINGS").hexdigest()

    leaf_hashes: list[str] = []
    for f in findings:
        # Check if finding has stable fingerprint
        if hasattr(f, "fingerprint") and f.fingerprint and hasattr(f.fingerprint, "primary_hash"):
            leaf_hashes.append(str(f.fingerprint.primary_hash))
        else:
            # Deterministic fallback leaf hash
            raw = f"{f.rule_id}:{f.location.file_path}:{f.location.line_start}:{f.code_snippet.strip()}"
            leaf_hashes.append(hashlib.sha256(raw.encode("utf-8")).hexdigest())

    leaf_hashes.sort()

    # Build Merkle tree upwards
    current_level = leaf_hashes
    while len(current_level) > 1:
        next_level: list[str] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


def sign_attestation(
    statement: ScanAttestationStatement,
    secret_key: str,
    key_id: str = "codesentinel-hmac-key-1",
) -> VerifiableAttestationEnvelope:
    """Sign an in-toto attestation statement using HMAC-SHA256, returning a DSSE envelope."""
    payload_bytes = canonical_json_bytes(statement)
    b64_payload = base64.b64encode(payload_bytes).decode("ascii")

    # In DSSE, signature is over: PAE(payloadType, payload)
    # PAE: "DSSEv1" + len(payloadType) + payloadType + len(payload) + payload
    pae_preimage = (
        f"DSSEv1 {len('application/vnd.in-toto+json')} application/vnd.in-toto+json "
        f"{len(payload_bytes)} "
    ).encode("utf-8") + payload_bytes

    sig_bytes = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=pae_preimage,
        digestmod=hashlib.sha256,
    ).digest()
    b64_sig = base64.b64encode(sig_bytes).decode("ascii")

    return VerifiableAttestationEnvelope(
        payload=b64_payload,
        payloadType="application/vnd.in-toto+json",
        signatures=[{"keyid": key_id, "sig": b64_sig}],
    )


def verify_attestation(
    envelope: VerifiableAttestationEnvelope,
    secret_key: str,
) -> tuple[bool, str, Optional[ScanAttestationStatement]]:
    """Verify cryptographic authenticity of a DSSE attestation envelope.

    Returns:
        (is_valid, message, optional_deserialized_statement)
    """
    if envelope.payloadType != "application/vnd.in-toto+json":
        return False, f"Unsupported payloadType: {envelope.payloadType}", None

    try:
        payload_bytes = base64.b64decode(envelope.payload.encode("ascii"))
    except Exception as e:
        return False, f"Invalid base64 payload: {e}", None

    pae_preimage = (
        f"DSSEv1 {len('application/vnd.in-toto+json')} application/vnd.in-toto+json "
        f"{len(payload_bytes)} "
    ).encode("utf-8") + payload_bytes

    expected_sig = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=pae_preimage,
        digestmod=hashlib.sha256,
    ).digest()
    b64_expected = base64.b64encode(expected_sig).decode("ascii")

    matching = any(s.get("sig") == b64_expected for s in envelope.signatures)
    if not matching:
        return False, "Attestation signature verification failed (tampered payload or incorrect key)", None

    try:
        stmt_dict = json.loads(payload_bytes.decode("utf-8"))
        statement = ScanAttestationStatement.model_validate(stmt_dict)
        return True, "Attestation verified successfully", statement
    except Exception as e:
        return False, f"Payload conforms to signature but is invalid Statement JSON: {e}", None
