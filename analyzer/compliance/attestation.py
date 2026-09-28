"""Cryptographically verifiable scan attestations (in-toto & DSSE) for CodeSentinel (Phase 26/27)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import unicodedata
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
    config_fingerprint: str = ""          # ConfigFingerprint.global_hash or config digest
    findings_merkle_root: str             # Merkle root of sorted finding hashes
    suppressions_digest: str              # SHA-256 of active suppressions
    compliance_scores: dict[str, float] = Field(default_factory=dict)
    gate_verdict: str = "PASS"            # "PASS", "FAIL", "WARN"
    cryptographic_assurance: str = "SYMMETRIC_AUTHENTICATION_ONLY"


class ScanAttestationStatement(BaseModel):
    """in-toto v1.0 Statement envelope with alias-safe serialization."""
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    type_: str = Field(default="https://in-toto.io/Statement/v1", alias="_type")
    subject: list[dict[str, str]] = Field(default_factory=list)
    predicateType: str = "https://codesentinel.dev/attestation/compliance/v1"
    predicate: AttestationPredicate

    @property
    def _type(self) -> str:
        return self.type_


class VerifiableAttestationEnvelope(BaseModel):
    """DSSE (Dead Simple Signing Envelope) formatted cryptographic attestation."""
    payload: str                         # Base64-encoded canonical JSON of ScanAttestationStatement
    payloadType: str = "application/vnd.in-toto+json"
    signatures: list[dict[str, str]] = Field(default_factory=list)


def _serialize_jcs_value(val: Any) -> str:
    """Recursively serialize arbitrary Python object to RFC 8785 canonical JSON string."""
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise ValueError(f"RFC 8785 forbids NaN and Infinity in numbers: {val}")
        # Format integers cleanly without .0
        if val.is_integer():
            return str(int(val))
        # Standard ECMAScript shortest float format
        s = repr(val)
        if "e+" in s:
            s = s.replace("e+", "e")
        return s
    elif isinstance(val, str):
        # Normalize to Unicode NFC
        norm_str = unicodedata.normalize("NFC", val)
        # RFC 8785 character escaping: only escape quotation mark, reverse solidus, and control characters 0x00-0x1f
        escaped_chars = []
        for ch in norm_str:
            cp = ord(ch)
            if cp == 0x22:
                escaped_chars.append('\\"')
            elif cp == 0x5C:
                escaped_chars.append('\\\\')
            elif cp < 0x20:
                if cp == 0x08:
                    escaped_chars.append('\\b')
                elif cp == 0x09:
                    escaped_chars.append('\\t')
                elif cp == 0x0A:
                    escaped_chars.append('\\n')
                elif cp == 0x0C:
                    escaped_chars.append('\\f')
                elif cp == 0x0D:
                    escaped_chars.append('\\r')
                else:
                    escaped_chars.append(f"\\u{cp:04x}")
            else:
                escaped_chars.append(ch)
        return '"' + "".join(escaped_chars) + '"'
    elif isinstance(val, (list, tuple)):
        items = [_serialize_jcs_value(elem) for elem in val]
        return "[" + ",".join(items) + "]"
    elif isinstance(val, dict):
        # RFC 8785: Keys MUST be sorted by UTF-16 code units / lexicographical UTF-8 bytes
        sorted_keys = sorted(val.keys(), key=lambda k: k.encode("utf-8"))
        pairs = []
        for k in sorted_keys:
            serialized_k = _serialize_jcs_value(str(k))
            serialized_v = _serialize_jcs_value(val[k])
            pairs.append(f"{serialized_k}:{serialized_v}")
        return "{" + ",".join(pairs) + "}"
    elif isinstance(val, BaseModel):
        # Convert using alias if defined
        return _serialize_jcs_value(val.model_dump(by_alias=True, exclude_none=True))
    else:
        # Fallback to string representation
        return _serialize_jcs_value(str(val))


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize object to deterministic, canonical RFC 8785 JSON bytes."""
    jcs_str = _serialize_jcs_value(data)
    return jcs_str.encode("utf-8")


def compute_findings_merkle_root(findings: list[Finding]) -> str:
    """Compute a deterministic, domain-separated binary Merkle tree root (RFC 6962 style).
    
    Leaves are prefixed with 0x00; internal nodes are prefixed with 0x01.
    Pairs raw 32-byte digests to prevent second-preimage and length-extension attacks.
    """
    if not findings:
        return hashlib.sha256(b"EMPTY_FINDINGS").hexdigest()

    # Extract finding fingerprints deterministically
    leaf_digests: list[bytes] = []
    for f in findings:
        if hasattr(f, "fingerprint") and f.fingerprint and hasattr(f.fingerprint, "primary_hash"):
            leaf_content = str(f.fingerprint.primary_hash)
        else:
            leaf_content = f"{f.rule_id}:{f.location.file_path}:{f.location.line_start}:{f.code_snippet.strip()}"

        # Domain separation for leaves: \x00 + payload
        leaf_hash = hashlib.sha256(b"\x00" + leaf_content.encode("utf-8")).digest()
        leaf_digests.append(leaf_hash)

    # Sort leaf digests deterministically
    leaf_digests.sort()

    # Build Merkle tree upwards
    current_level = leaf_digests
    while len(current_level) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(current_level):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
                # Domain separation for interior nodes: \x01 + left + right
                combined = hashlib.sha256(b"\x01" + left + right).digest()
                next_level.append(combined)
                i += 2
            else:
                # Odd node: carry up directly with height domain separation
                isolated = hashlib.sha256(b"\x01" + left + left).digest()
                next_level.append(isolated)
                i += 1
        current_level = next_level

    return current_level[0].hex()


def sign_attestation(
    statement: ScanAttestationStatement,
    secret_key: str,
    key_id: str = "codesentinel-hmac-key-1",
) -> VerifiableAttestationEnvelope:
    """Sign an in-toto attestation statement using HMAC-SHA256, returning a DSSE envelope."""
    if not secret_key:
        raise ValueError("Cannot sign attestation: secret_key cannot be empty")

    payload_bytes = canonical_json_bytes(statement)
    b64_payload = base64.b64encode(payload_bytes).decode("ascii")

    # In DSSE, signature is over: PAE(payloadType, payload)
    # PAE: "DSSEv1" + " " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
    payload_type = "application/vnd.in-toto+json"
    pae_preimage = (
        f"DSSEv1 {len(payload_type.encode('utf-8'))} {payload_type} "
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
        payloadType=payload_type,
        signatures=[{"keyid": key_id, "sig": b64_sig}],
    )


def verify_attestation(
    envelope: VerifiableAttestationEnvelope,
    secret_key: str,
) -> tuple[bool, str, Optional[ScanAttestationStatement]]:
    """Verify cryptographic authenticity of a DSSE attestation envelope with constant-time equality.

    Returns:
        (is_valid, message, optional_deserialized_statement)
    """
    if not secret_key:
        return False, "Verification failed: verification secret_key cannot be empty", None

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

    # Constant-time comparison to prevent timing attacks
    matching = any(
        hmac.compare_digest(s.get("sig", ""), b64_expected)
        for s in envelope.signatures
    )
    if not matching:
        return False, "Attestation signature verification failed (tampered payload or incorrect key)", None

    try:
        stmt_dict = json.loads(payload_bytes.decode("utf-8"))
        statement = ScanAttestationStatement.model_validate(stmt_dict)
        return True, "Attestation verified successfully", statement
    except Exception as e:
        return False, f"Payload conforms to signature but is invalid Statement JSON: {e}", None
