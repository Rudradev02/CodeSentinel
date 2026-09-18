"""End-to-end integration tests for Phase 7 pipeline, CLI arguments, and reporters."""

import json
from pathlib import Path
from analyzer.cli.main import main
from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.results import AnalysisResult
from analyzer.reporting.terminal import TerminalReporter


def test_e2e_max_component_depth_cli(tmp_path, capsys):
    fixture_path = str(Path(__file__).resolve().parent / "fixtures" / "phase7" / "layered_clean_project")
    
    # Run with --max-component-depth 1
    ret = main(["analyze", fixture_path, "--max-component-depth", "1", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    
    assert parsed["graph"]["component_graph"] is not None
    # With depth 1, components should be domain, application, presentation, infrastructure
    node_ids = {n["id"] for n in parsed["graph"]["component_graph"]["nodes"]}
    assert "domain" in node_ids
    assert "application" in node_ids
    assert "presentation" in node_ids
    assert "infrastructure" in node_ids


def test_e2e_terminal_reporter_output(capsys):
    fixture_path = str(Path(__file__).resolve().parent / "fixtures" / "phase7" / "layered_inverted_project")
    ret = main(["analyze", fixture_path])
    assert ret == 0
    captured = capsys.readouterr()
    
    assert "CODESENTINEL REPOSITORY STATIC ANALYSIS REPORT" in captured.out
    assert "CODEBASE HEALTH GRADE:" in captured.out
    assert "Architecture Health :" in captured.out
    assert "Security Posture    :" in captured.out
    assert "COMPONENT GRAPH" in captured.out
    assert "ARC-005" in captured.out


def test_e2e_json_schema_round_trip():
    fixture_path = str(Path(__file__).resolve().parent / "fixtures" / "phase7" / "sdp_violation_project")
    pipeline = AnalysisPipeline()
    result = pipeline.run(fixture_path)

    json_str = result.model_dump_json()
    loaded = AnalysisResult.model_validate_json(json_str)

    assert loaded.id == result.id
    assert loaded.graph.component_graph is not None
    assert loaded.health is not None
    assert loaded.health.overall_score == result.health.overall_score
    assert len(loaded.graph.component_graph.nodes) == len(result.graph.component_graph.nodes)
