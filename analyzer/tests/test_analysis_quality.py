"""Quality, boundary, determinism, and edge case tests for CodeSentinel analysis engine."""

import json
from pathlib import Path
import networkx as nx
import pytest

from analyzer.architecture.rules.arc_002_coupling import RuleArc002
from analyzer.architecture.rules.arc_003_god_module import RuleArc003
from analyzer.architecture.rules.arc_004_deep_chain import RuleArc004
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.graph import (
    ArchitectureGraph,
    CouplingMetrics,
    DependencyEdge,
    DependencyNode,
)
from analyzer.models.results import AnalysisStatus
from analyzer.reporting.json_reporter import JsonReporter


def test_empty_repository_handling(tmp_path):
    """An empty repository must analyze cleanly with 0 files and 0 findings, not crash."""
    pipeline = AnalysisPipeline()
    result = pipeline.run(tmp_path, repository_name="Empty Repo")

    assert result.status == AnalysisStatus.COMPLETED
    assert result.repository.total_files == 0
    assert result.repository.total_loc == 0
    assert result.repository.detected_languages == {}
    assert result.repository.detected_frameworks == []
    assert len(result.security_findings) == 0
    assert len(result.architecture_findings) == 0
    assert len(result.files) == 0
    assert len(result.parsing_errors) == 0
    assert result.graph.metrics.total_modules == 0


def test_unsupported_only_repository_handling(tmp_path):
    """A repository with only non-code files must succeed cleanly with 0 analyzable files."""
    (tmp_path / "README.md").write_text("# Project Documentation\nSome notes here.")
    (tmp_path / "data.csv").write_text("id,name\n1,alice\n2,bob")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    pipeline = AnalysisPipeline()
    result = pipeline.run(tmp_path, repository_name="Docs Only Repo")

    assert result.status == AnalysisStatus.COMPLETED
    assert result.repository.total_files == 0
    assert len(result.security_findings) == 0
    assert len(result.architecture_findings) == 0


def test_single_file_repository_with_finding(tmp_path):
    """A minimal single-file repository should detect security vulnerabilities correctly."""
    (tmp_path / "script.py").write_text('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE12"\n')

    pipeline = AnalysisPipeline()
    result = pipeline.run(tmp_path)

    assert result.repository.total_files == 1
    assert result.repository.total_loc >= 1
    assert len(result.security_findings) == 1
    assert result.security_findings[0].rule_id == "SEC-PY-001"


def test_arc_002_coupling_threshold_boundary():
    """Verify exact boundary behavior for ARC-002: fan_out <= threshold has no finding, fan_out > threshold has finding."""
    rule = RuleArc002(threshold=10)

    # Case 1: fan_out == 10 (at boundary) -> no finding
    node_at_boundary = DependencyNode(
        id="mod_a.py",
        file_path="mod_a.py",
        module_name="mod_a",
        language="PYTHON",
        fan_out=10,
    )
    graph_1 = ArchitectureGraph(
        nodes=[node_at_boundary],
        edges=[],
        metrics=CouplingMetrics(total_modules=1),
    )
    assert len(rule.analyze(graph_1)) == 0

    # Case 2: fan_out == 11 (exceeds threshold) -> finding
    node_exceeding = DependencyNode(
        id="mod_b.py",
        file_path="mod_b.py",
        module_name="mod_b",
        language="PYTHON",
        fan_out=11,
    )
    graph_2 = ArchitectureGraph(
        nodes=[node_exceeding],
        edges=[],
        metrics=CouplingMetrics(total_modules=1),
    )
    findings = rule.analyze(graph_2)
    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-002"


def test_arc_003_god_module_threshold_boundary():
    """Verify exact boundary behavior for ARC-003 God Module heuristic."""
    rule = RuleArc003(loc_threshold_1=500, fan_out_threshold_1=8, fan_in_threshold_1=5)

    # Exactly at thresholds (500, 8, 5) -> no finding
    node_boundary = DependencyNode(
        id="hub.py",
        file_path="hub.py",
        module_name="hub",
        language="PYTHON",
        loc=500,
        fan_out=8,
        fan_in=5,
    )
    graph_1 = ArchitectureGraph(nodes=[node_boundary], edges=[], metrics=CouplingMetrics(total_modules=1))
    assert len(rule.analyze(graph_1)) == 0

    # Exceeding all 3 thresholds (501, 9, 6) -> finding
    node_god = DependencyNode(
        id="hub_god.py",
        file_path="hub_god.py",
        module_name="hub_god",
        language="PYTHON",
        loc=501,
        fan_out=9,
        fan_in=6,
    )
    graph_2 = ArchitectureGraph(nodes=[node_god], edges=[], metrics=CouplingMetrics(total_modules=1))
    findings = rule.analyze(graph_2)
    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-003"
    assert node_god.is_god_module is True


def test_arc_004_deep_chain_threshold_boundary():
    """Verify exact boundary behavior for ARC-004: chain length 5 has no finding, chain length 6 triggers finding."""
    rule = RuleArc004(depth_threshold=5)

    # 6 nodes chained linearly -> 5 edges/hops (depth = 5) -> at boundary, no finding
    nodes_5 = [
        DependencyNode(id=f"m{i}.py", file_path=f"m{i}.py", module_name=f"m{i}", language="PYTHON")
        for i in range(6)
    ]
    edges_5 = [
        DependencyEdge(source=f"m{i}.py", target=f"m{i+1}.py", is_external=False)
        for i in range(5)
    ]
    graph_5 = ArchitectureGraph(nodes=nodes_5, edges=edges_5, metrics=CouplingMetrics(total_modules=6))
    assert len(rule.analyze(graph_5)) == 0

    # 7 nodes chained linearly -> 6 edges/hops (depth = 6) -> exceeds 5, finding
    nodes_6 = [
        DependencyNode(id=f"m{i}.py", file_path=f"m{i}.py", module_name=f"m{i}", language="PYTHON")
        for i in range(7)
    ]
    edges_6 = [
        DependencyEdge(source=f"m{i}.py", target=f"m{i+1}.py", is_external=False)
        for i in range(6)
    ]
    graph_6 = ArchitectureGraph(nodes=nodes_6, edges=edges_6, metrics=CouplingMetrics(total_modules=7))
    findings = rule.analyze(graph_6)
    assert len(findings) == 1
    assert findings[0].rule_id == "ARC-004"


def test_dependency_classification_integrity(sample_repo_path):
    """Verify STDLIB, EXTERNAL, and LOCAL dependencies are properly distinguished."""
    pipeline = AnalysisPipeline()
    result = pipeline.run(sample_repo_path)

    edge_map = {(e.source, e.target): e for e in result.graph.edges}

    # Python stdlib
    assert edge_map[("backend/app.py", "os")].dependency_category == "STDLIB"
    assert edge_map[("backend/app.py", "sys")].dependency_category == "STDLIB"

    # External dependencies
    assert edge_map[("backend/app.py", "flask")].dependency_category == "EXTERNAL"
    assert edge_map[("frontend/App.tsx", "react")].dependency_category == "EXTERNAL"

    # Local dependencies
    assert edge_map[("backend/models/user.py", "backend/services/user_service.py")].dependency_category == "LOCAL"


def test_architecture_metrics_consistency(sample_repo_path):
    """Verify that graph nodes contains all nodes while total_modules accurately counts local modules only."""
    pipeline = AnalysisPipeline()
    result = pipeline.run(sample_repo_path)

    total_nodes = len(result.graph.nodes)
    local_nodes = [n for n in result.graph.nodes if not n.is_external]
    external_nodes = [n for n in result.graph.nodes if n.is_external]

    assert total_nodes == 11
    assert len(local_nodes) == 7
    assert len(external_nodes) == 4
    assert result.graph.metrics.total_modules == len(local_nodes)


def test_repeated_analysis_determinism(sample_repo_path):
    """Repeated analysis on the same repository must produce identical findings, graphs, and sorted JSON collections."""
    pipeline = AnalysisPipeline()

    result_1 = pipeline.run(sample_repo_path)
    result_2 = pipeline.run(sample_repo_path)

    # Findings identity
    assert len(result_1.architecture_findings) == len(result_2.architecture_findings)
    for f1, f2 in zip(result_1.architecture_findings, result_2.architecture_findings):
        assert f1.rule_id == f2.rule_id
        assert f1.location == f2.location
        assert f1.severity == f2.severity
        assert f1.code_snippet == f2.code_snippet

    # Graph nodes & edges identity
    assert [n.id for n in result_1.graph.nodes] == [n.id for n in result_2.graph.nodes]
    assert [(e.source, e.target) for e in result_1.graph.edges] == [(e.source, e.target) for e in result_2.graph.edges]

    # Deterministic JSON structure (excluding wall-clock duration and timestamps)
    json_reporter = JsonReporter()
    dict_1 = json.loads(json_reporter.render(result_1))
    dict_2 = json.loads(json_reporter.render(result_2))

    # Strip runtime metadata for comparison
    for d in (dict_1, dict_2):
        d.pop("id", None)
        d.pop("metadata", None)

    assert dict_1 == dict_2
