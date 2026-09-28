"""Tests for hash-chained tamper-evident audit trail ledger."""

import json
import pytest
from analyzer.compliance.audit_trail import AuditEvent, AuditEventType, AuditTrailLedger


def test_empty_audit_ledger_is_valid():
    """Verify empty ledger passes integrity check."""
    ledger = AuditTrailLedger()
    valid, msg = ledger.verify_integrity()
    assert valid is True
    assert "empty" in msg


def test_audit_ledger_hash_chain_linking():
    """Verify events are sequentially chained via previous_event_hash."""
    ledger = AuditTrailLedger()
    e0 = ledger.append_event(AuditEventType.SCAN_START, {"path": "/repo"}, timestamp="2026-09-28T12:00:00Z")
    assert e0.sequence_number == 0
    assert e0.previous_event_hash == AuditTrailLedger.GENESIS_HASH

    e1 = ledger.append_event(AuditEventType.RULE_PACK_LOADED, {"pack": "pci-dss-v4"}, timestamp="2026-09-28T12:00:01Z")
    assert e1.sequence_number == 1
    assert e1.previous_event_hash == e0.event_hash

    e2 = ledger.append_event(AuditEventType.GATE_DECISION, {"verdict": "PASS"}, timestamp="2026-09-28T12:00:02Z")
    assert e2.sequence_number == 2
    assert e2.previous_event_hash == e1.event_hash

    valid, msg = ledger.verify_integrity()
    assert valid is True
    assert "3 events valid" in msg


def test_audit_ledger_detects_payload_tampering():
    """Verify tampering with details in an event invalidates the ledger."""
    ledger = AuditTrailLedger()
    ledger.append_event(AuditEventType.SCAN_START, {"path": "/repo"})
    ledger.append_event(AuditEventType.GATE_DECISION, {"verdict": "PASS"})

    # Tamper event details in memory
    tampered_event = ledger._events[1].model_copy(update={"details": {"verdict": "FAIL"}})
    ledger._events[1] = tampered_event

    valid, msg = ledger.verify_integrity()
    assert valid is False
    assert "Tampered event payload" in msg


def test_audit_ledger_export_jsonl():
    """Verify JSON-L export correctly formats each event as a single JSON line."""
    ledger = AuditTrailLedger()
    ledger.append_event(AuditEventType.SCAN_START, {"target": "proj"})
    ledger.append_event(AuditEventType.ATTESTATION_SEALED, {"sig": "sig123"})

    jsonl_str = ledger.export_jsonl()
    lines = jsonl_str.strip().split("\n")
    assert len(lines) == 2
    parsed0 = json.loads(lines[0])
    assert parsed0["event_type"] == "SCAN_START"
    parsed1 = json.loads(lines[1])
    assert parsed1["event_type"] == "ATTESTATION_SEALED"
