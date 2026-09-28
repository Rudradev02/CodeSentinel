"""Tamper-evident, hash-chained audit ledger for CodeSentinel compliance (Phase 26)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import uuid
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditEventType(str, Enum):
    """Categorization of audit events recorded in the compliance ledger."""
    SCAN_START = "SCAN_START"
    RULE_PACK_LOADED = "RULE_PACK_LOADED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    FINDING_DETECTED = "FINDING_DETECTED"
    SUPPRESSION_APPLIED = "SUPPRESSION_APPLIED"
    COMPLIANCE_EVALUATED = "COMPLIANCE_EVALUATED"
    GATE_DECISION = "GATE_DECISION"
    ATTESTATION_SEALED = "ATTESTATION_SEALED"


class AuditEvent(BaseModel):
    """A single immutably hash-chained event record in the audit trail."""
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sequence_number: int
    timestamp: str                       # ISO-8601 UTC
    event_type: AuditEventType
    actor: str = "codesentinel-engine"
    details: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str
    event_hash: str


class AuditTrailLedger:
    """Append-only, cryptographically linked audit ledger."""

    GENESIS_HASH = "0" * 64

    def __init__(self):
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def _compute_event_hash(
        self,
        seq: int,
        ts: str,
        evt_type: str,
        actor: str,
        details: dict[str, Any],
        prev_hash: str,
    ) -> str:
        """Compute deterministic SHA-256 hash of event fields."""
        serialized_details = json.dumps(details, sort_keys=True, separators=(",", ":"))
        preimage = f"{seq}|{ts}|{evt_type}|{actor}|{serialized_details}|{prev_hash}"
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()

    def append_event(
        self,
        event_type: AuditEventType,
        details: Optional[dict[str, Any]] = None,
        actor: str = "codesentinel-engine",
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Append a new audit event, automatically linking to the previous event hash."""
        seq = len(self._events)
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        clean_details = details or {}
        prev_hash = self._events[-1].event_hash if self._events else self.GENESIS_HASH

        evt_hash = self._compute_event_hash(
            seq=seq,
            ts=ts,
            evt_type=event_type.value,
            actor=actor,
            details=clean_details,
            prev_hash=prev_hash,
        )

        event = AuditEvent(
            sequence_number=seq,
            timestamp=ts,
            event_type=event_type,
            actor=actor,
            details=clean_details,
            previous_event_hash=prev_hash,
            event_hash=evt_hash,
        )
        self._events.append(event)
        return event

    def verify_integrity(self) -> tuple[bool, str]:
        """Verify the cryptographic chain of custody of the entire ledger.

        Returns:
            (is_valid, description_message)
        """
        if not self._events:
            return True, "Audit ledger is empty (valid)"

        expected_prev = self.GENESIS_HASH
        for idx, event in enumerate(self._events):
            if event.sequence_number != idx:
                return False, f"Broken sequence number at event {idx}: expected {idx}, got {event.sequence_number}"

            if event.previous_event_hash != expected_prev:
                return (
                    False,
                    f"Tampered hash chain at event {idx}: previous_hash {event.previous_event_hash} != {expected_prev}",
                )

            recomputed_hash = self._compute_event_hash(
                seq=event.sequence_number,
                ts=event.timestamp,
                evt_type=event.event_type.value,
                actor=event.actor,
                details=event.details,
                prev_hash=event.previous_event_hash,
            )

            if event.event_hash != recomputed_hash:
                return (
                    False,
                    f"Tampered event payload at event {idx}: event_hash {event.event_hash} != recomputed {recomputed_hash}",
                )

            expected_prev = event.event_hash

        return True, f"Audit ledger verified ({len(self._events)} events valid)"

    def export_jsonl(self) -> str:
        """Export ledger events as JSON Lines (JSON-L)."""
        lines = []
        for e in self._events:
            lines.append(json.dumps(e.model_dump(exclude_none=True), sort_keys=True))
        return "\n".join(lines)
