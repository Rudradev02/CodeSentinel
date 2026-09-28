"""Tamper-evident, hash-chained audit ledger for CodeSentinel compliance (Phase 26/27)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
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
    SCAN_TERMINATED = "SCAN_TERMINATED"


class GenesisHeader(BaseModel):
    """Root identity block anchoring the ledger to a specific repository and analysis run."""
    model_config = ConfigDict(frozen=True)

    chain_id: str
    chain_version: str = "1.0"
    repository_id: str = "default-repo"
    commit_hash: Optional[str] = None
    tool_version: str = "0.1.0"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditEvent(BaseModel):
    """A single immutably hash-chained event record in the audit trail."""
    model_config = ConfigDict(frozen=True)

    chain_id: str = "default-chain"
    event_id: str
    sequence_number: int
    timestamp: str                       # ISO-8601 UTC
    event_type: AuditEventType
    actor: str = "codesentinel-engine"
    details: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str
    event_hash: str


class AuditTrailLedger:
    """Append-only, cryptographically linked audit ledger with genesis binding and terminal seal."""

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        repository_id: str = "default-repo",
        chain_id: Optional[str] = None,
        commit_hash: Optional[str] = None,
    ):
        self.repository_id = repository_id
        self.chain_id = chain_id or hashlib.sha256(f"{repository_id}:{commit_hash or 'HEAD'}".encode("utf-8")).hexdigest()[:16]
        self.genesis = GenesisHeader(
            chain_id=self.chain_id,
            repository_id=repository_id,
            commit_hash=commit_hash,
        )
        self._events: list[AuditEvent] = []
        self._is_sealed: bool = False

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def _compute_event_hash(
        self,
        chain_id: str,
        event_id: str,
        seq: int,
        ts: str,
        evt_type: str,
        actor: str,
        details: dict[str, Any],
        prev_hash: str,
    ) -> str:
        """Compute deterministic SHA-256 hash of event fields including event_id and chain_id."""
        serialized_details = json.dumps(details, sort_keys=True, separators=(",", ":"))
        preimage = f"{chain_id}|{event_id}|{seq}|{ts}|{evt_type}|{actor}|{serialized_details}|{prev_hash}"
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()

    def append_event(
        self,
        event_type: AuditEventType,
        details: Optional[dict[str, Any]] = None,
        actor: str = "codesentinel-engine",
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Append a new audit event, automatically linking to the previous event hash."""
        if self._is_sealed and event_type != AuditEventType.SCAN_TERMINATED:
            raise ValueError("Audit ledger is already sealed; no further events can be appended.")

        seq = len(self._events)
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        clean_details = details or {}
        prev_hash = self._events[-1].event_hash if self._events else self.GENESIS_HASH

        # Deterministic event_id derived from chain_id and sequence number
        event_id = hashlib.sha256(f"{self.chain_id}:{seq}".encode("utf-8")).hexdigest()[:16]

        evt_hash = self._compute_event_hash(
            chain_id=self.chain_id,
            event_id=event_id,
            seq=seq,
            ts=ts,
            evt_type=event_type.value,
            actor=actor,
            details=clean_details,
            prev_hash=prev_hash,
        )

        event = AuditEvent(
            chain_id=self.chain_id,
            event_id=event_id,
            sequence_number=seq,
            timestamp=ts,
            event_type=event_type,
            actor=actor,
            details=clean_details,
            previous_event_hash=prev_hash,
            event_hash=evt_hash,
        )
        self._events.append(event)
        if event_type == AuditEventType.SCAN_TERMINATED:
            self._is_sealed = True
        return event

    def seal_ledger(self, details: Optional[dict[str, Any]] = None) -> AuditEvent:
        """Append terminal SCAN_TERMINATED event sealing the ledger against future appending or truncation."""
        seal_details = dict(details or {})
        seal_details["total_events_sealed"] = len(self._events) + 1
        seal_details["chain_id"] = self.chain_id
        return self.append_event(AuditEventType.SCAN_TERMINATED, details=seal_details)

    def verify_integrity(self, expected_chain_id: Optional[str] = None) -> tuple[bool, str]:
        """Verify the cryptographic chain of custody of the entire ledger.

        Returns:
            (is_valid, description_message)
        """
        if not self._events:
            return True, "Audit ledger is empty (valid)"

        target_chain = expected_chain_id or self._events[0].chain_id
        expected_prev = self.GENESIS_HASH

        for idx, event in enumerate(self._events):
            if event.sequence_number != idx:
                return False, f"Broken sequence number at event {idx}: expected {idx}, got {event.sequence_number}"

            if event.chain_id != target_chain:
                return False, f"Cross-chain replay detected at event {idx}: event chain_id {event.chain_id} != expected {target_chain}"

            expected_id = hashlib.sha256(f"{target_chain}:{idx}".encode("utf-8")).hexdigest()[:16]
            if event.event_id != expected_id:
                return False, f"Nondeterministic event ID at event {idx}: expected {expected_id}, got {event.event_id}"

            if event.previous_event_hash != expected_prev:
                return (
                    False,
                    f"Tampered hash chain at event {idx}: previous_hash {event.previous_event_hash} != {expected_prev}",
                )

            recomputed_hash = self._compute_event_hash(
                chain_id=event.chain_id,
                event_id=event.event_id,
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

        # Check terminal seal if present
        last_event = self._events[-1]
        if last_event.event_type == AuditEventType.SCAN_TERMINATED:
            sealed_count = last_event.details.get("total_events_sealed")
            if sealed_count and sealed_count != len(self._events):
                return False, f"Ledger truncation detected: sealed {sealed_count} events but found {len(self._events)}"

        return True, f"Audit ledger verified ({len(self._events)} events valid)"

    def export_jsonl(self) -> str:
        """Export ledger events as JSON Lines (JSON-L)."""
        lines = []
        for e in self._events:
            lines.append(json.dumps(e.model_dump(exclude_none=True), sort_keys=True))
        return "\n".join(lines)
