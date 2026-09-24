"""Unit tests for Phase 16 CLI and Pipeline Configuration Integration."""

import pytest
from pathlib import Path
from analyzer.cli.main import build_parser, main
from analyzer.config.repo_config import RepoConfig, AnalysisSectionConfig
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_cli_phase16_arguments():
    parser = build_parser()
    args = parser.parse_args([
        "analyze", ".",
        "--disable-type-inference",
        "--disable-context-sensitivity",
        "--max-k", "1",
        "--max-contexts-per-function", "4",
        "--max-summary-iterations", "3",
    ])
    assert args.disable_type_inference is True
    assert args.disable_context_sensitivity is True
    assert args.max_k == 1
    assert args.max_contexts_per_function == 4
    assert args.max_summary_iterations == 3


def test_repo_config_phase16_defaults_and_hash():
    cfg = RepoConfig()
    assert cfg.analysis.disable_type_inference is False
    assert cfg.analysis.disable_context_sensitivity is False
    assert cfg.analysis.max_k == 2
    assert cfg.analysis.max_contexts_per_function == 8
    assert cfg.analysis.max_summary_iterations == 5
    
    # Hash is deterministic
    h1 = cfg.compute_hash()
    h2 = cfg.compute_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_analysis_config_phase16_fields():
    config = AnalysisConfig(
        disable_type_inference=True,
        disable_context_sensitivity=True,
        max_k=1,
        max_contexts_per_function=6,
        max_summary_iterations=4,
    )
    assert config.disable_type_inference is True
    assert config.disable_context_sensitivity is True
    assert config.max_k == 1
    assert config.max_contexts_per_function == 6
    assert config.max_summary_iterations == 4


def test_pipeline_call_graph_summary_includes_phase16_metrics(tmp_path):
    # Minimal repo with 1 python file
    p = tmp_path / "main.py"
    p.write_text("def run():\n    x = 1\n", encoding="utf-8")

    config = AnalysisConfig()
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    assert "type_resolution" in result.call_graph_summary
    assert "context_sensitivity" in result.call_graph_summary
    tr = result.call_graph_summary["type_resolution"]
    assert "types_inferred" in tr
    assert "type_aware_edges" in tr
    assert "confidence_distribution" in tr
    cs = result.call_graph_summary["context_sensitivity"]
    assert "total_contexts" in cs
    assert "max_depth_reached" in cs
