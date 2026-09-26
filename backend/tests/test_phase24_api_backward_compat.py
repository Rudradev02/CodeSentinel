"""Tests for Phase 24 backend API schema backward compatibility and boundary independence."""

import importlib
import inspect
from pathlib import Path
from backend.app.schemas.analysis import FindingDTO, ProofObligationDTO


def test_proof_obligation_dto_serialization():
    """Verify ProofObligationDTO instantiates and serializes as expected."""
    obl = ProofObligationDTO(
        obligation_id="OBL_AUTH_01",
        policy_id="POL-SQL-01",
        kind="REQUIRES_AUTHENTICATION",
        target_sink_category="SQL_EXECUTE",
        state="PROVEN_SAFE",
        evidence_details="Route protected by JWT middleware",
    )
    dumped = obl.model_dump(mode="json")
    assert dumped["obligation_id"] == "OBL_AUTH_01"
    assert dumped["state"] == "PROVEN_SAFE"
    assert dumped["unknown_reason"] is None


def test_finding_dto_with_phase24_proof_obligations():
    """Verify FindingDTO accepts and preserves Phase 24 proof_obligations in dataflow_evidence."""
    obligations = [
        {
            "obligation_id": "OBL_AUTH_01",
            "policy_id": "POL-SQL-01",
            "kind": "REQUIRES_AUTHENTICATION",
            "target_sink_category": "SQL_EXECUTE",
            "state": "PROVEN_SAFE",
            "evidence_details": "Route protected by session decorator",
        },
        {
            "obligation_id": "OBL_PROP_01",
            "policy_id": "POL-SQL-01",
            "kind": "REQUIRES_PROPERTY",
            "required_property": "SQL_SAFE",
            "state": "UNKNOWN",
            "evidence_details": "Property SQL_SAFE indeterminate",
            "unknown_reason": "No sanitizer dominating query sink",
        },
    ]

    finding_data = {
        "id": "find-phase24-001",
        "rule_id": "SEC-PY-001",
        "rule_name": "SQL Injection Raw String Concatenation",
        "category": "SECURITY",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "SQL statement dynamically concatenated with untrusted input",
        "remediation": "Use parameterized queries or ORM",
        "message": "Untrusted input reaches SQL execute sink",
        "location": {
            "file_path": "backend/app.py",
            "line_start": 15,
        },
        "evidence": {
            "snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        },
        "dataflow_evidence": {
            "proof_obligations": obligations,
            "unknown_reasons": ["No sanitizer dominating query sink"],
        },
    }

    dto = FindingDTO.model_validate(finding_data)
    assert dto.id == "find-phase24-001"
    assert dto.dataflow_evidence is not None
    assert len(dto.dataflow_evidence["proof_obligations"]) == 2
    assert dto.dataflow_evidence["proof_obligations"][1]["state"] == "UNKNOWN"
    assert dto.dataflow_evidence["proof_obligations"][1]["unknown_reason"] == "No sanitizer dominating query sink"


def test_finding_dto_backward_compat_legacy_findings():
    """Verify FindingDTO deserializes historical findings without Phase 24 fields."""
    legacy_finding = {
        "id": "find-legacy-001",
        "rule_id": "SEC-PY-001",
        "rule_name": "Hardcoded Secret",
        "category": "SECURITY",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Hardcoded secret detected",
        "remediation": "Move to env vars",
        "message": "Secret key in source",
        "location": {
            "file_path": "config.py",
            "line_start": 1,
        },
        "evidence": {
            "snippet": "SECRET = 'xyz'",
        },
    }

    dto = FindingDTO.model_validate(legacy_finding)
    assert dto.id == "find-legacy-001"
    assert dto.dataflow_evidence is None


def test_strict_boundary_independence_analyzer_has_no_backend_or_ai_imports():
    """Verify analyzer modules never import backend, sqlalchemy, langchain, or external AI packages."""
    forbidden = ["backend", "sqlalchemy", "openai", "anthropic", "langchain"]
    analyzer_dir = Path("analyzer")

    for py_file in analyzer_dir.rglob("*.py"):
        if "tests" in py_file.parts:
            continue
        content = py_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                for pkg in forbidden:
                    assert not (f"import {pkg}" in stripped or f"from {pkg}" in stripped), (
                        f"Boundary violation: {py_file} imports forbidden '{pkg}' in line: {stripped}"
                    )
