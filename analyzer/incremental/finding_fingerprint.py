"""Stable, content-addressable finding fingerprint computation (Phase 25).

Produces deterministic fingerprints for findings that survive across analysis
runs, line shifts, minor refactors, and cross-platform path normalization.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


def _norm_path_for_fingerprint(path: str) -> str:
    """Normalize file path for deterministic fingerprinting.

    - Replace backslashes with forward slashes.
    - Strip leading/trailing slashes.
    - Lowercase for case-insensitive matching.
    """
    return path.replace("\\", "/").strip("/").lower()


def _norm_snippet_for_fingerprint(snippet: Optional[str]) -> str:
    """Normalize code snippet by collapsing whitespace."""
    if not snippet:
        return ""
    return " ".join(snippet.strip().split())


class FindingFingerprint(BaseModel):
    """Deterministic, content-addressable identity for a security/architecture finding.

    - ``primary_hash``: Stable across line shifts (rule_id + path + snippet).
    - ``location_hash``: Incorporates line/column for disambiguation.
    - ``composite_hash``: Includes policy/obligation context when available.
    - ``stable_id``: Human-readable identifier ``CS-{rule_id}-{hash[:12]}``.
    """

    model_config = ConfigDict(frozen=True)

    primary_hash: str = Field(..., description="SHA-256 of (rule_id, normalized_path, normalized_snippet)")
    location_hash: str = Field(..., description="SHA-256 of (rule_id, normalized_path, line_start, col_start)")
    composite_hash: str = Field(default="", description="SHA-256 incorporating policy/obligation context")
    stable_id: str = Field(..., description="Human-readable stable identifier CS-{rule_id}-{hash[:12]}")


def compute_finding_fingerprint(
    rule_id: str,
    file_path: str,
    code_snippet: str,
    line_start: int = 0,
    col_start: int = 0,
    policy_id: Optional[str] = None,
    obligation_kinds: Optional[list[str]] = None,
) -> FindingFingerprint:
    """Compute a stable FindingFingerprint for a finding.

    Args:
        rule_id: The rule ID producing the finding.
        file_path: Repository-relative file path.
        code_snippet: The relevant source code extract.
        line_start: Starting line number (1-indexed).
        col_start: Starting column offset.
        policy_id: Optional associated policy ID.
        obligation_kinds: Optional sorted obligation kind strings.

    Returns:
        A frozen FindingFingerprint with deterministic hashes.
    """
    norm_path = _norm_path_for_fingerprint(file_path)
    norm_snippet = _norm_snippet_for_fingerprint(code_snippet)

    # Primary hash: stable across line shifts
    primary_payload = f"{rule_id}:{norm_path}:{norm_snippet}"
    primary_hash = hashlib.sha256(primary_payload.encode("utf-8")).hexdigest()

    # Location hash: incorporates position for disambiguation
    location_payload = f"{rule_id}:{norm_path}:{line_start}:{col_start}"
    location_hash = hashlib.sha256(location_payload.encode("utf-8")).hexdigest()

    # Composite hash: includes policy context when available
    composite_hash = ""
    if policy_id or obligation_kinds:
        sorted_obligations = sorted(obligation_kinds) if obligation_kinds else []
        composite_payload = f"{primary_hash}:{policy_id or ''}:{','.join(sorted_obligations)}"
        composite_hash = hashlib.sha256(composite_payload.encode("utf-8")).hexdigest()

    # Human-readable stable ID
    stable_id = f"CS-{rule_id}-{primary_hash[:12]}"

    return FindingFingerprint(
        primary_hash=primary_hash,
        location_hash=location_hash,
        composite_hash=composite_hash,
        stable_id=stable_id,
    )


def compute_fingerprint_for_finding(finding: object) -> FindingFingerprint:
    """Compute a FindingFingerprint from an existing Finding model instance.

    Extracts rule_id, file_path, code_snippet, and location coordinates
    from the finding and delegates to ``compute_finding_fingerprint``.
    """
    rule_id = getattr(finding, "rule_id", "UNKNOWN")
    location = getattr(finding, "location", None)
    file_path = getattr(location, "file_path", "") if location else ""
    line_start = getattr(location, "line_start", 0) if location else 0
    col_start = getattr(location, "col_start", 0) or 0 if location else 0
    code_snippet = getattr(finding, "code_snippet", "")

    return compute_finding_fingerprint(
        rule_id=rule_id,
        file_path=file_path,
        code_snippet=code_snippet,
        line_start=line_start,
        col_start=col_start,
    )
