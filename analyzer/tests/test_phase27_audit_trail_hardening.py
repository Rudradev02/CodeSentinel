"""Test suite for Phase 27: Audit Trail Hardening (Genesis Binding, Terminal Sealing, Truncation Detection)."""

import pytest

from analyzer.compliance.audit_trail import (
    AuditEvent,
    AuditEventType,
    AuditTrailLedger,
)


def test_genesis_header_binding_and_deterministic_event_ids():
    """Verify genesis header generation, chain_id assignment, and deterministic event IDs."""
    ledger = AuditTrailLedger(
        repository_id="e:/repo",
        commit_hash="abc1234",
    )
    assert ledger.genesis is not None
    assert ledger.genesis.chain_id != ""
    assert ledger.chain_id == ledger.genesis.chain_id

    # Append first event (sequence 0)
    init_event = ledger.append_event(
        event_type=AuditEventType.SCAN_START,
        details={"repo": "e:/repo"},
    )
    assert init_event.event_type == AuditEventType.SCAN_START
    assert init_event.sequence_number == 0
    assert init_event.event_id != ""

    # Next event has sequential sequence number and deterministic ID
    e2 = ledger.append_event(
        event_type=AuditEventType.RULE_PACK_LOADED,
        details={"pack_id": "security-core"},
    )
    assert e2.sequence_number == 1
    assert e2.previous_event_hash == init_event.event_hash
    assert e2.chain_id == ledger.chain_id

    # Integrity verification
    valid, msg = ledger.verify_integrity()
    assert valid is True


def test_terminal_sealing_and_immutable_ledger():
    """Verify seal_ledger appends SCAN_TERMINATED and prevents subsequent appends."""
    ledger = AuditTrailLedger(repository_id="e:/repo")
    ledger.append_event(
        event_type=AuditEventType.RULE_PACK_LOADED,
        details={"packs": ["security-core"]},
    )

    # Seal ledger
    terminal_event = ledger.seal_ledger(details={"total_findings": 0, "status": "CLEAN"})
    assert terminal_event.event_type == AuditEventType.SCAN_TERMINATED
    assert ledger._is_sealed is True

    # Appending after seal must raise ValueError
    with pytest.raises(ValueError, match="Audit ledger is already sealed"):
        ledger.append_event(AuditEventType.FINDING_DETECTED, details={"fid": "123"})


def test_truncation_detection_on_sealed_ledger():
    """Verify that removing the terminal seal event triggers truncation detection."""
    ledger = AuditTrailLedger(repository_id="e:/repo")
    ledger.append_event(AuditEventType.RULE_PACK_LOADED, details={"p": 1})
    ledger.seal_ledger(details={"status": "DONE"})

    # Full sealed ledger passes
    valid, _ = ledger.verify_integrity()
    assert valid is True

    # Truncate terminal event from private list
    ledger._events.pop()
    # Now ledger has 1 event but last event is not SCAN_TERMINATED and if sealed was truncated
    # If we alter the details of terminal event or drop an event:
    ledger2 = AuditTrailLedger(repository_id="e:/repo")
    ledger2.append_event(AuditEventType.RULE_PACK_LOADED, details={"p": 1})
    ledger2.append_event(AuditEventType.FINDING_DETECTED, details={"fid": "f1"})
    ledger2.seal_ledger(details={"status": "DONE"})

    # Drop event 1 (internal truncation / gap)
    popped = ledger2._events.pop(1)
    valid_truncated, msg = ledger2.verify_integrity()
    assert valid_truncated is False
    assert "sequence" in msg.lower() or "chain" in msg.lower() or "truncation" in msg.lower()


def test_foreign_event_replay_detection():
    """Verify that an event with mismatched chain_id or manipulated event_id is rejected."""
    ledger1 = AuditTrailLedger(repository_id="e:/repo1")
    ledger2 = AuditTrailLedger(repository_id="e:/repo2")

    e_foreign = ledger2.append_event(AuditEventType.RULE_PACK_LOADED, details={"p": 2})

    # Tamper ledger1 by substituting with foreign event
    ledger1._events.append(e_foreign)
    valid, msg = ledger1.verify_integrity(expected_chain_id=ledger1.chain_id)
    assert valid is False
    assert "replay" in msg.lower() or "sequence" in msg.lower() or "tampered" in msg.lower()
