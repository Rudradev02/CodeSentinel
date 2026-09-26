"""Tests for Phase 23 backend API schema backward compatibility and boundary independence."""

import importlib
import inspect
from backend.app.schemas.analysis import FindingDTO


def test_finding_dto_with_phase23_trust_boundary_and_policy():
    """Verify FindingDTO accepts and preserves Phase 23 trust_boundary and policy_evaluation."""
    trust_boundary_dict = {
        "boundary_id": "TB_FLASK_ROUTE_12",
        "boundary_type": "HTTP_REQUEST_PARAM",
        "framework": "FLASK",
        "file_path": "backend/app.py",
        "line": 12,
        "column": 0,
        "symbol_name": "user_id",
        "route_pattern": "/api/users/<user_id>",
        "http_method": "GET",
        "is_authenticated": "AUTHENTICATED",
        "is_authorized": "PERMISSION_GRANTED",
        "boundary_confidence": "HIGH",
        "details": "Flask URL route parameter",
    }

    policy_evaluation_dict = {
        "policy_id": "POL-SQL-01",
        "policy_name": "SQL Query Parameterization & Safety",
        "evaluation_result": "PROVEN_VIOLATION",
        "satisfied_properties": [],
        "missing_properties": ["SQL_SAFE"],
        "details": "Policy POL-SQL-01 violated. Missing required properties: SQL_SAFE",
    }

    finding_data = {
        "id": "find-phase23-001",
        "rule_id": "SEC-PY-005",
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
            "trust_boundary": trust_boundary_dict,
            "policy_evaluation": policy_evaluation_dict,
        },
    }

    dto = FindingDTO.model_validate(finding_data)
    assert dto.id == "find-phase23-001"
    assert dto.dataflow_evidence is not None
    assert dto.dataflow_evidence["trust_boundary"]["boundary_id"] == "TB_FLASK_ROUTE_12"
    assert dto.dataflow_evidence["trust_boundary"]["framework"] == "FLASK"
    assert dto.dataflow_evidence["policy_evaluation"]["policy_id"] == "POL-SQL-01"
    assert dto.dataflow_evidence["policy_evaluation"]["evaluation_result"] == "PROVEN_VIOLATION"

    dumped = dto.model_dump(mode="json")
    assert dumped["dataflow_evidence"]["trust_boundary"]["framework"] == "FLASK"
    assert dumped["dataflow_evidence"]["policy_evaluation"]["policy_id"] == "POL-SQL-01"


def test_finding_dto_backward_compat_omitted_phase23_fields():
    """Verify FindingDTO deserializes historical findings without Phase 23 fields."""
    legacy_finding = {
        "id": "find-legacy-001",
        "rule_id": "SEC-PY-001",
        "rule_name": "Hardcoded Secret",
        "category": "SECURITY",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Hardcoded secret detected",
        "remediation": "Move secrets to environment variables",
        "message": "Hardcoded secret in settings.py",
        "location": {
            "file_path": "settings.py",
            "line_start": 10,
        },
        "evidence": {
            "snippet": "API_KEY = 'secret123'",
        },
    }

    dto = FindingDTO.model_validate(legacy_finding)
    assert dto.id == "find-legacy-001"
    assert dto.dataflow_evidence is None


def test_phase23_boundary_independence():
    """Verify analyzer modules for Phase 23 have strictly zero backend/infrastructure imports."""
    phase23_modules = [
        "analyzer.models.boundary",
        "analyzer.dataflow.properties",
        "analyzer.frameworks.base",
        "analyzer.frameworks.flask",
        "analyzer.frameworks.django",
        "analyzer.frameworks.express",
        "analyzer.frameworks.react",
        "analyzer.rules.policy",
    ]

    forbidden_prefixes = ("backend", "app", "fastapi", "sqlalchemy", "celery", "redis")

    for mod_name in phase23_modules:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        for line in source.splitlines():
            line_clean = line.strip()
            if line_clean.startswith("import ") or line_clean.startswith("from "):
                for forbidden in forbidden_prefixes:
                    assert not line_clean.startswith(f"import {forbidden}"), (
                        f"Forbidden import in {mod_name}: {line_clean}"
                    )
                    assert not line_clean.startswith(f"from {forbidden}"), (
                        f"Forbidden import in {mod_name}: {line_clean}"
                    )
