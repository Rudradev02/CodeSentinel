"""Tests for Phase 22 backend API schema backwards compatibility and security evidence chains."""

from backend.app.schemas.analysis import (
    AnalysisResultDTO,
    FindingDTO,
    IncrementalStatsDTO,
)
from backend.app.schemas.callgraph import (
    CallGraphSummaryDTO,
    IncrementalSummaryDTO,
)


def test_incremental_summary_dto_phase22_fields():
    """Verify IncrementalSummaryDTO serializes and deserializes Phase 22 fields."""
    data = {
        "analysis_mode": "incremental",
        "files_discovered": 10,
        "files_reused": 8,
        "files_reanalyzed": 2,
        "cache_hits": 8,
        "cache_misses": 2,
        "hit_ratio": 0.8,
        "composition_hits": 5,
        "composition_misses": 1,
        "taint_summary_hits": 7,
        "taint_summary_misses": 2,
    }
    dto = IncrementalSummaryDTO.model_validate(data)
    assert dto.composition_hits == 5
    assert dto.composition_misses == 1
    assert dto.taint_summary_hits == 7
    assert dto.taint_summary_misses == 2

    dumped = dto.model_dump(mode="json")
    assert dumped["composition_hits"] == 5
    assert dumped["taint_summary_hits"] == 7


def test_incremental_summary_dto_backward_compat_omitted_phase22_fields():
    """Verify IncrementalSummaryDTO backward compatibility when Phase 22 fields are omitted."""
    data = {
        "analysis_mode": "incremental",
        "files_discovered": 5,
        "files_reused": 5,
        "files_reanalyzed": 0,
        "cache_hits": 5,
        "cache_misses": 0,
        "hit_ratio": 1.0,
    }
    dto = IncrementalSummaryDTO.model_validate(data)
    assert dto.composition_hits == 0
    assert dto.composition_misses == 0
    assert dto.taint_summary_hits == 0
    assert dto.taint_summary_misses == 0


def test_finding_dto_with_security_evidence_chain():
    """Verify FindingDTO accepts and preserves Phase 22 security_chain evidence payload."""
    chain_dict = {
        "taint_source": {
            "source_category": "HTTP_PARAM",
            "file_path": "app/views.py",
            "line": 10,
            "expression": "request.GET['q']",
        },
        "propagation_chain": [
            {
                "step_index": 0,
                "file_path": "app/views.py",
                "line": 12,
                "operation": "CALL_ARG",
                "is_interprocedural": True,
                "callee_qn": "db.execute_query",
            }
        ],
        "taint_sink": {
            "sink_category": "SQL_EXECUTE",
            "rule_id": "SEC-PY-011",
            "file_path": "app/db.py",
            "line": 42,
            "callee_name": "cursor.execute",
        },
        "chain_confidence": "HIGH",
        "chain_depth": 1,
        "chain_hash": "a" * 64,
    }

    finding_data = {
        "id": "find-12345",
        "rule_id": "SEC-PY-011",
        "rule_name": "SQL Injection Interprocedural",
        "category": "SECURITY",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Untrusted input reaches SQL sink across module boundary",
        "remediation": "Use parameterized queries",
        "message": "Untrusted input reaches SQL sink",
        "location": {
            "file_path": "app/views.py",
            "line_start": 42,
        },
        "evidence": {
            "snippet": "cursor.execute(query)",
        },
        "dataflow_evidence": {
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "security_chain": chain_dict,
        },
    }

    dto = FindingDTO.model_validate(finding_data)
    assert dto.id == "find-12345"
    assert dto.dataflow_evidence is not None
    assert "security_chain" in dto.dataflow_evidence
    chain_data = dto.dataflow_evidence["security_chain"]
    assert chain_data["chain_depth"] == 1
    assert chain_data["chain_hash"] == "a" * 64
    assert chain_data["taint_source"]["source_category"] == "HTTP_PARAM"


def test_incremental_stats_dto_phase22_fields():
    """Verify IncrementalStatsDTO handles Phase 22 counters."""
    stats = IncrementalStatsDTO(
        analysis_mode="incremental",
        files_discovered=20,
        files_reused=15,
        files_reanalyzed=5,
        composition_hits=12,
        composition_misses=3,
        taint_summary_hits=14,
        taint_summary_misses=1,
    )
    assert stats.composition_hits == 12
    assert stats.composition_misses == 3
    assert stats.taint_summary_hits == 14
    assert stats.taint_summary_misses == 1
