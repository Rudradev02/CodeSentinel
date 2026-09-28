"""Test suite for Phase 27: Audit Trail Hardening (Genesis Binding, Terminal Sealing, Truncation Detection)."""

import pytest

from analyzer.compliance.audit_trail import (
    AuditEvent,
    AuditEventType,
    AuditTrailLedger,
    compute_event_hash,
)


def test_genesis_header_binding_and_deterministic_event_ids():
    """Verify genesis header generation, chain_id assignment, and deterministic event IDs."""
    ledger = AuditTrailLedger.create_for_scan(
        repository_path="e:/repo",
        git_commit_hash="abc1234",
        tool_version="0.1.0",
    )
    assert ledger.genesis_header is not None
    assert ledger.genesis_header.chain_id != ""
    assert ledger.chain_id == ledger.genesis_header.chain_id
    assert len(ledger.events) == 1

    init_event = ledger.events[0]
    assert init_event.event_type == AuditEventType.SCAN_INITIATED
    assert init_event.sequence_number == 0
    assert init_event.event_id != ""

    # Next event has sequential sequence number and deterministic ID
    e2 = ledger.append_event(
        event_type=AuditEventType.RULE_PACK_RESOLVED,
        payload={"pack_id": "security-core"},
    )
    assert e2.sequence_number == 1
    assert e2.prev_event_hash == init_event.event_hash
    assert e2.chain_id == ledger.chain_id

    # Integrity verification
    valid, msg = ledger.verify_integrity()
    assert valid is True


def test_terminal_sealing_and_immutable_ledger():
    """Verify seal_ledger appends SCAN_TERMINATED and prevents subsequent appends."""
    ledger = AuditTrailLedger.create_for_scan("e:/repo")
    ledger.append_event(
        event_type=AuditEventType.RULE_PACK_RESOLVED,
        payload={"packs": ["security-core"]},
    )

    # Seal ledger
    terminal_event = ledger.seal_ledger(summary={"total_findings": 0, "status": "CLEAN"})
    assert terminal_event.event_type == AuditEventType.SCAN_TERMINATED
    assert ledger.is_sealed is True

    # Appending after seal must raise RuntimeError
    with pytest.raises(RuntimeError, match="Cannot append event to sealed audit trail ledger"):
        ledger.append_event(AuditEventType.FINDING_RECORDED, payload={"fid": "123"})

    # Calling seal_ledger twice must raise RuntimeError
    with pytest.raises(RuntimeError, match="Audit trail ledger is already sealed"):
        ledger.seal_ledger()


def test_truncation_detection_on_sealed_ledger():
    """Verify that removing the terminal seal event triggers truncation detection."""
    ledger = AuditTrailLedger.create_for_scan("e:/repo")
    ledger.append_event(AuditEventType.RULE_PACK_RESOLVED, payload={"p": 1})
    ledger.seal_ledger(summary={"status": "DONE"})

    # Full sealed ledger passes
    valid, _ = ledger.verify_integrity()
    assert valid is True

    # Truncate terminal event
    ledger.events.pop()
    valid_truncated, msg = ledger.verify_integrity()
    assert valid_truncated is False
    assert "Truncation detected" in msg or "SCAN_TERMINATED" in msg


def test_foreign_event_replay_detection():
    """Verify that an event with mismatched chain_id or manipulated event_id is rejected."""
    ledger1 = AuditTrailLedger.create_for_scan("e:/repo1")
    ledger2 = AuditTrailLedger.create_for_scan("e:/repo2")

    e_foreign = ledger2.append_event(AuditEventType.RULE_PACK_RESOLVED, payload={"p": 2})

    # Tamper ledger1 by substituting with foreign event
    ledger1.events.append(e_foreign)
    valid, msg = ledger1.verify_integrity()
    assert valid is False
    assert "Chain ID mismatch" in msg or "Sequence mismatch" in msg or "hash mismatch" in msg
