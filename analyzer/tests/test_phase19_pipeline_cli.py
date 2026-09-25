"""Unit tests for Phase 19 CLI and Pipeline Configuration Integration."""

import pytest
from pathlib import Path
from analyzer.cli.main import build_parser
from analyzer.config.repo_config import RepoConfig
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_cli_phase19_arguments():
    """Verify that CLI flags for Phase 19 are properly registered and parsed."""
    parser = build_parser()
    args = parser.parse_args([
        "analyze", ".",
        "--disable-interprocedural-contracts",
        "--max-summary-iterations", "7",
        "--max-cached-contracts", "1500",
        "--max-effects-per-summary", "24",
        "--max-field-effect-depth", "4",
    ])
    assert args.disable_interprocedural_contracts is True
    assert args.max_summary_iterations == 7
    assert args.max_cached_contracts == 1500
    assert args.max_effects_per_summary == 24
    assert args.max_field_effect_depth == 4


def test_repo_config_phase19_defaults_and_hash():
    """Verify repo_config defaults for Phase 19 and config hash determinism."""
    cfg = RepoConfig()
    assert cfg.analysis.disable_interprocedural_contracts is False
    assert cfg.analysis.max_summary_iterations == 5
    assert cfg.analysis.max_cached_contracts == 2000
    assert cfg.analysis.max_effects_per_summary == 16
    assert cfg.analysis.max_field_effect_depth == 3

    h1 = cfg.compute_hash()
    h2 = cfg.compute_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_analysis_config_phase19_fields():
    """Verify AnalysisConfig initialization with Phase 19 fields."""
    config = AnalysisConfig(
        disable_interprocedural_contracts=True,
        max_summary_iterations=3,
        max_cached_contracts=500,
        max_effects_per_summary=8,
        max_field_effect_depth=2,
    )
    assert config.disable_interprocedural_contracts is True
    assert config.max_summary_iterations == 3
    assert config.max_cached_contracts == 500
    assert config.max_effects_per_summary == 8
    assert config.max_field_effect_depth == 2


def test_pipeline_with_phase19_disabled(tmp_path: Path):
    """Verify that pipeline runs cleanly when interprocedural contracts are disabled."""
    p_code = """
def test_fn(x):
    return x
"""
    (tmp_path / "app.py").write_text(p_code, encoding="utf-8")
    pipeline = AnalysisPipeline()
    config = AnalysisConfig(disable_interprocedural_contracts=True)
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.call_graph_summary is not None
    # When disabled, contracts key should not be populated in summary
    assert "contracts" not in result.call_graph_summary
