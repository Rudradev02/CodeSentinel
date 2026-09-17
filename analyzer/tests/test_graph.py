"""Tests for architecture dependency graph construction, metrics, and cycle detection."""

from pathlib import Path
import pytest

from analyzer.architecture.graph_builder import ArchitectureGraphBuilder
from analyzer.architecture.metrics import ArchitectureMetricsCalculator
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_graph_builder_and_cycle_detection(sample_repo_path):
    files, _ = discover_repository_files(sample_repo_path)
    py_parser = PythonParser()
    ts_parser = TypeScriptParser()

    parsed_files = []
    for f in files:
        path = Path(f.path)
        content = path.read_text(encoding="utf-8", errors="replace")
        if f.language == "PYTHON":
            parsed_files.append(py_parser.parse(path, f.relative_path, content))
        elif f.language == "TYPESCRIPT":
            parsed_files.append(ts_parser.parse(path, f.relative_path, content))

    resolver = DependencyResolver(files)
    resolver.resolve_all(parsed_files)

    builder = ArchitectureGraphBuilder(files, parsed_files)
    G, raw_nodes, raw_edges = builder.build()

    graph = ArchitectureMetricsCalculator.compute(G, raw_nodes, raw_edges)

    # 1. Verify Nodes
    node_ids = {n.id for n in graph.nodes if not n.is_external}
    assert "backend/services/user_service.py" in node_ids
    assert "backend/models/user.py" in node_ids
    assert "frontend/App.tsx" in node_ids
    assert "frontend/components/Button.tsx" in node_ids

    # 2. Verify Cycle Detection: user_service <-> user
    assert len(graph.circular_dependencies) >= 1
    cycle_modules_sets = [set(c.modules) for c in graph.circular_dependencies]

    expected_cycle = {"backend/services/user_service.py", "backend/models/user.py"}
    assert expected_cycle in cycle_modules_sets

    # 3. Verify Circular Edge Marking
    circular_edges = [e for e in graph.edges if e.is_circular]
    assert len(circular_edges) >= 2

    # 4. Verify Metrics
    assert graph.metrics.total_modules == len(node_ids)
    assert graph.metrics.circular_cycles_count >= 1
    assert graph.metrics.density >= 0.0

    # 5. Verify God-module detection is NOT applied in Phase 2
    for node in graph.nodes:
        assert node.is_god_module is False
