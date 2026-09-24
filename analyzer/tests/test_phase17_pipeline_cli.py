"""Unit tests for Phase 17 CLI and Pipeline Configuration Integration."""

import pytest
from pathlib import Path
from analyzer.cli.main import build_parser
from analyzer.config.repo_config import RepoConfig, AnalysisSectionConfig
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_cli_phase17_arguments():
    parser = build_parser()
    args = parser.parse_args([
        "analyze", ".",
        "--disable-alias-analysis",
        "--disable-field-sensitivity",
        "--max-points-to-candidates", "6",
        "--max-fields-per-object", "20",
        "--max-objects-per-function", "40",
        "--max-alias-iterations", "7",
    ])
    assert args.disable_alias_analysis is True
    assert args.disable_field_sensitivity is True
    assert args.max_points_to_candidates == 6
    assert args.max_fields_per_object == 20
    assert args.max_objects_per_function == 40
    assert args.max_alias_iterations == 7


def test_repo_config_phase17_defaults_and_hash():
    cfg = RepoConfig()
    assert cfg.analysis.disable_alias_analysis is False
    assert cfg.analysis.disable_field_sensitivity is False
    assert cfg.analysis.max_points_to_candidates == 4
    assert cfg.analysis.max_fields_per_object == 16
    assert cfg.analysis.max_objects_per_function == 32
    assert cfg.analysis.max_alias_iterations == 5

    # Deterministic hash computation
    h1 = cfg.compute_hash()
    h2 = cfg.compute_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_analysis_config_phase17_fields():
    config = AnalysisConfig(
        disable_alias_analysis=True,
        disable_field_sensitivity=True,
        max_points_to_candidates=2,
        max_fields_per_object=8,
        max_objects_per_function=16,
        max_alias_iterations=3,
    )
    assert config.disable_alias_analysis is True
    assert config.disable_field_sensitivity is True
    assert config.max_points_to_candidates == 2
    assert config.max_fields_per_object == 8
    assert config.max_objects_per_function == 16
    assert config.max_alias_iterations == 3


def test_pipeline_call_graph_summary_includes_phase17_metrics(tmp_path):
    p = tmp_path / "main.py"
    p.write_text("def run():\n    x = 1\n    y = x\n", encoding="utf-8")

    config = AnalysisConfig()
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    assert "alias_analysis" in result.call_graph_summary
    aa = result.call_graph_summary["alias_analysis"]
    assert "abstract_objects_count" in aa
    assert "alias_bindings_count" in aa


def test_pipeline_disable_alias_analysis(tmp_path):
    p = tmp_path / "main.py"
    p.write_text("def run():\n    x = 1\n", encoding="utf-8")

    config = AnalysisConfig(disable_alias_analysis=True)
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    aa = result.call_graph_summary.get("alias_analysis")
    assert aa is not None
    assert aa["alias_bindings_count"] == 0
