"""Unit tests for Phase 18 CLI and Pipeline Configuration Integration."""

import pytest
from pathlib import Path
from analyzer.cli.main import build_parser
from analyzer.config.repo_config import RepoConfig, AnalysisSectionConfig
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_cli_phase18_arguments():
    parser = build_parser()
    args = parser.parse_args([
        "analyze", ".",
        "--disable-path-sensitivity",
        "--disable-guard-analysis",
        "--max-active-paths", "16",
        "--max-total-path-states", "256",
        "--max-branch-depth", "8",
        "--max-conditions-per-path", "32",
        "--max-cfg-blocks", "128",
    ])
    assert args.disable_path_sensitivity is True
    assert args.disable_guard_analysis is True
    assert args.max_active_paths == 16
    assert args.max_total_path_states == 256
    assert args.max_branch_depth == 8
    assert args.max_conditions_per_path == 32
    assert args.max_cfg_blocks == 128


def test_repo_config_phase18_defaults_and_hash():
    cfg = RepoConfig()
    assert cfg.analysis.disable_path_sensitivity is False
    assert cfg.analysis.disable_guard_analysis is False
    assert cfg.analysis.max_active_paths == 8
    assert cfg.analysis.max_total_path_states == 128
    assert cfg.analysis.max_branch_depth == 6
    assert cfg.analysis.max_conditions_per_path == 16
    assert cfg.analysis.max_cfg_blocks == 64

    # Deterministic hash computation
    h1 = cfg.compute_hash()
    h2 = cfg.compute_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_analysis_config_phase18_fields():
    config = AnalysisConfig(
        disable_path_sensitivity=True,
        disable_guard_analysis=True,
        max_active_paths=4,
        max_total_path_states=64,
        max_branch_depth=4,
        max_conditions_per_path=8,
        max_cfg_blocks=32,
    )
    assert config.disable_path_sensitivity is True
    assert config.disable_guard_analysis is True
    assert config.max_active_paths == 4
    assert config.max_total_path_states == 64
    assert config.max_branch_depth == 4
    assert config.max_conditions_per_path == 8
    assert config.max_cfg_blocks == 32


def test_pipeline_call_graph_summary_includes_phase18_metrics(tmp_path):
    p = tmp_path / "main.py"
    p.write_text("def run():\n    x = 1\n    if x > 0:\n        y = 2\n", encoding="utf-8")

    config = AnalysisConfig()
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    assert "path_sensitivity" in result.call_graph_summary
    ps = result.call_graph_summary["path_sensitivity"]
    assert "cfg_blocks_analyzed" in ps
    assert "guards_evaluated" in ps
    assert "guarded_paths_pruned" in ps
    assert "paths_truncated_budget" in ps


def test_pipeline_disable_path_sensitivity(tmp_path):
    p = tmp_path / "main.py"
    p.write_text("def run():\n    x = 1\n", encoding="utf-8")

    config = AnalysisConfig(disable_path_sensitivity=True)
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    ps = result.call_graph_summary.get("path_sensitivity")
    assert ps is None
