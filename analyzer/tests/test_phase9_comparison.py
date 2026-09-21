"""Unit tests for Phase 9 baseline differential comparison engine."""

from analyzer.comparison.diff import BaselineComparator
from analyzer.models.comparison import FindingTransition
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import (
    ArchitectureGraph,
    ComponentEdge,
    ComponentGraph,
    ComponentNode,
    PackageMetrics,
)
from analyzer.models.results import (
    AnalysisResult,
    CodebaseHealth,
    RepositoryInfo,
    SubScore,
)


def _make_finding(
    rule_id: str,
    file_path: str,
    line: int,
    snippet: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    finding_id: str = None,
) -> Finding:
    kwargs = {
        "rule_id": rule_id,
        "rule_name": f"Rule {rule_id}",
        "category": FindingCategory.SECURITY,
        "evidence_type": EvidenceType.DETERMINISTIC,
        "severity": severity,
        "confidence": FindingConfidence.HIGH,
        "location": SourceLocation(
            file_path=file_path,
            line_start=line,
            line_end=line,
        ),
        "code_snippet": snippet,
        "description": f"Test violation {rule_id}",
        "remediation": "Fix it",
    }
    if finding_id:
        kwargs["id"] = finding_id
    return Finding(**kwargs)


def test_baseline_finding_transitions():
    """Verify classification of NEW, RESOLVED, UNCHANGED, and MODIFIED findings."""
    f_unchanged_base = _make_finding("SEC-001", "app/auth.py", 10, "key = 'secret'")
    f_unchanged_curr = _make_finding("SEC-001", "app/auth.py", 10, "key = 'secret'")

    f_shifted_base = _make_finding("SEC-002", "app/api.py", 20, "eval(user_input)")
    # Line shifted from 20 to 25 due to code insertion above
    f_shifted_curr = _make_finding("SEC-002", "app/api.py", 25, "eval(user_input)")

    f_resolved_base = _make_finding("SEC-003", "app/db.py", 5, "raw_sql_query()")

    f_new_curr = _make_finding("SEC-004", "app/routes.py", 50, "pickle.loads(payload)")

    repo_base = RepositoryInfo(name="test", local_path="/repo", total_files=3, commit_hash="c1")
    repo_curr = RepositoryInfo(name="test", local_path="/repo", total_files=3, commit_hash="c2")

    base_result = AnalysisResult(
        repository=repo_base,
        security_findings=[f_unchanged_base, f_shifted_base, f_resolved_base],
    )
    curr_result = AnalysisResult(
        repository=repo_curr,
        security_findings=[f_unchanged_curr, f_shifted_curr, f_new_curr],
    )

    comparison = BaselineComparator.compare(curr_result, base_result)

    assert comparison.summary.total_baseline == 3
    assert comparison.summary.total_current == 3
    assert comparison.summary.unchanged_count == 1
    assert comparison.summary.modified_count == 1
    assert comparison.summary.resolved_count == 1
    assert comparison.summary.new_count == 1

    # Check finding transitions
    transitions = {df.finding.rule_id: df.transition for df in comparison.findings}
    assert transitions["SEC-001"] == FindingTransition.UNCHANGED
    assert transitions["SEC-002"] == FindingTransition.MODIFIED
    assert transitions["SEC-003"] == FindingTransition.RESOLVED
    assert transitions["SEC-004"] == FindingTransition.NEW

    # Check regression breakdown
    assert comparison.summary.new_by_severity.get("HIGH") == 1
    assert comparison.summary.resolved_by_severity.get("HIGH") == 1


def test_baseline_health_delta():
    """Verify calculation of overall and domain health score deltas."""
    repo = RepositoryInfo(name="test", local_path="/repo", total_files=5)

    base_health = CodebaseHealth(
        overall_score=75.0,
        overall_grade="C",
        architecture_health=SubScore(score=80.0, grade="B"),
        security_posture=SubScore(score=70.0, grade="C"),
    )
    curr_health = CodebaseHealth(
        overall_score=88.5,
        overall_grade="B",
        architecture_health=SubScore(score=92.0, grade="A"),
        security_posture=SubScore(score=85.0, grade="B"),
    )

    base_result = AnalysisResult(repository=repo, health=base_health)
    curr_result = AnalysisResult(repository=repo, health=curr_health)

    comparison = BaselineComparator.compare(curr_result, base_result)

    assert comparison.health_delta is not None
    assert comparison.health_delta.score_delta == 13.5
    assert comparison.health_delta.baseline_score == 75.0
    assert comparison.health_delta.current_score == 88.5
    assert comparison.health_delta.baseline_grade == "C"
    assert comparison.health_delta.current_grade == "B"
    assert comparison.health_delta.grade_changed is True
    assert comparison.health_delta.architecture_score_delta == 12.0
    assert comparison.health_delta.security_score_delta == 15.0


def test_baseline_component_graph_delta():
    """Verify detection of new/removed components and instability delta."""
    repo = RepositoryInfo(name="test", local_path="/repo", total_files=5)

    node_c1_base = ComponentNode(
        id="comp1", path="comp1", metrics=PackageMetrics(instability=0.2)
    )
    node_c2_base = ComponentNode(
        id="comp2", path="comp2", metrics=PackageMetrics(instability=0.8)
    )
    cg_base = ComponentGraph(nodes=[node_c1_base, node_c2_base])

    node_c1_curr = ComponentNode(
        id="comp1", path="comp1", metrics=PackageMetrics(instability=0.5)  # Delta: +0.3
    )
    node_c3_curr = ComponentNode(
        id="comp3", path="comp3", metrics=PackageMetrics(instability=0.1)  # New component
    )
    cg_curr = ComponentGraph(nodes=[node_c1_curr, node_c3_curr])

    base_result = AnalysisResult(
        repository=repo,
        graph=ArchitectureGraph(component_graph=cg_base),
    )
    curr_result = AnalysisResult(
        repository=repo,
        graph=ArchitectureGraph(component_graph=cg_curr),
    )

    comparison = BaselineComparator.compare(curr_result, base_result)

    assert comparison.component_delta is not None
    assert comparison.component_delta.new_components == ["comp3"]
    assert comparison.component_delta.removed_components == ["comp2"]
    assert comparison.component_delta.instability_deltas.get("comp1") == 0.3
