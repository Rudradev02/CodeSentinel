"""Unit tests for Phase 18 Reporting and SARIF schema enrichment."""

import json
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.results import AnalysisResult, RepositoryInfo
from analyzer.reporting.markdown_reporter import MarkdownReporter
from analyzer.reporting.sarif import SarifReporter
from analyzer.reporting.terminal import TerminalReporter


def _create_sample_phase18_result():
    loc = SourceLocation(file_path="app/views.py", line_start=25, col_start=4)
    step = {
        "caller_function": "handle_request",
        "callee_function": "UserRepository.find_by_id",
        "caller_file": "app/views.py",
        "callee_file": "app/repo.py",
        "call_site_line": 26,
        "call_site_col": 8,
        "argument_index": 0,
        "callee_param_name": "user_id",
        "taint_action": "REACHES_SINK",
        "receiver_type": "app.repo.UserRepository",
        "receiver_confidence": "KNOWN",
        "context_id": "ctx-a1b2c3",
        "alias_path": "alias_repo -> repo",
        "field_path": "req.payload",
        "allocation_site": "ALLOC:app/views.py:25:4:UserRepository:handle_request",
        "path_condition": "user_id is not None",
        "branch_taken": "TRUE_BRANCH",
        "guard_predicate": "user_id is not None",
        "path_status": "FEASIBLE",
    }
    finding = Finding(
        id="finding-sarif-guard-1",
        rule_id="SEC-PY-011",
        rule_name="Cross-Function SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="alias_repo.find_by_id(uid)",
        description="SQL injection reaches sink with governing path condition",
        remediation="Use parameterized queries",
        evidence={
            "flow_type": "INTER_PROCEDURAL_TAINT",
            "path_summary": "request.args['id'] -> UserRepository.find_by_id() -> execute()",
            "call_chain": [step],
            "source": {"expression": "request.args['id']", "file_path": "app/views.py", "line": 24},
            "sink": {"callee": "execute", "file_path": "app/repo.py", "line": 50},
            "alias_evidence": [{"step": "step_0", "alias_path": "alias_repo -> repo"}],
            "field_evidence": [{"step": "step_0", "field_path": "req.payload"}],
        },
    )
    repo = RepositoryInfo(name="test-repo", local_path=".")
    return AnalysisResult(
        repository=repo,
        security_findings=[finding],
        architecture_findings=[],
        call_graph_summary={
            "total_functions": 10,
            "total_call_edges": 12,
            "resolved_local": 8,
            "resolved_import": 4,
            "unresolved": 0,
            "resolution_rate": 1.0,
            "summarized_functions": 10,
            "unsummarized_functions": 0,
            "interprocedural_findings_count": 1,
            "max_call_depth_reached": 2,
            "alias_analysis": {
                "abstract_objects_count": 5,
                "alias_bindings_count": 8,
                "field_edges_count": 4,
                "ambiguous_points_to_count": 0,
                "truncated_points_to_count": 0,
            },
            "path_sensitivity": {
                "cfg_blocks_analyzed": 42,
                "guards_evaluated": 15,
                "guarded_paths_pruned": 6,
                "paths_truncated_budget": 0,
            },
        },
    )


def test_terminal_reporter_path_sensitivity():
    result = _create_sample_phase18_result()
    reporter = TerminalReporter()
    output = reporter.render(result)
    assert "Path & Guard Analysis: 42 blocks" in output
    assert "15 guards" in output
    assert "6 paths pruned" in output
    assert "PATH SENSITIVITY & GUARDS (PHASE 18):" in output
    assert "CFG Blocks Analyzed : 42" in output
    assert "Guards Evaluated    : 15" in output
    assert "Guarded Paths Pruned: 6" in output
    assert "Condition: user_id is not None" in output
    assert "Branch: TRUE_BRANCH" in output
    assert "Guard: user_id is not None" in output


def test_markdown_reporter_path_sensitivity():
    result = _create_sample_phase18_result()
    reporter = MarkdownReporter()
    output = reporter.render(result)
    assert "Condition: `user_id is not None`" in output
    assert "Branch: `TRUE_BRANCH`" in output
    assert "Guard: `user_id is not None`" in output


def test_sarif_reporter_path_sensitivity():
    result = _create_sample_phase18_result()
    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    code_flows = results[0]["codeFlows"]
    assert len(code_flows) == 1
    locations = code_flows[0]["threadFlows"][0]["locations"]
    # Loc 0 is source, Loc 1 is call step, Loc 2 is sink
    assert len(locations) == 3
    call_step_loc = locations[1]
    props = call_step_loc.get("properties", {})
    assert props.get("pathCondition") == "user_id is not None"
    assert props.get("branchTaken") == "TRUE_BRANCH"
    assert props.get("guardPredicate") == "user_id is not None"
    assert props.get("pathStatus") == "FEASIBLE"


def test_reporters_without_phase18_metrics_backward_compat():
    """Verify all reporters handle results without Phase 18 call_graph_summary cleanly."""
    repo = RepositoryInfo(name="test-repo", local_path=".")
    result = AnalysisResult(
        repository=repo,
        security_findings=[],
        architecture_findings=[],
        call_graph_summary=None,
    )
    # Terminal reporter gracefully renders without crashing
    term_out = TerminalReporter().render(result)
    assert "CODESENTINEL" in term_out

    # Markdown reporter gracefully renders
    md_out = MarkdownReporter().render(result)
    assert "CodeSentinel Static Analysis Report" in md_out



    # SARIF reporter generates valid v2.1.0 output
    sarif_out = SarifReporter().render(result)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"

