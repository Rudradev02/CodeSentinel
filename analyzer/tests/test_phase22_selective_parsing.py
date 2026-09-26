"""Unit tests for Phase 22 selective parsing optimization in AnalysisPipeline."""

from pathlib import Path

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.incremental.cache import InMemoryAnalysisCache


def _setup_sample_repo(repo_path: Path):
    """Create a minimal 3-file Python repository."""
    (repo_path / "app").mkdir(parents=True, exist_ok=True)
    (repo_path / "app" / "views.py").write_text(
        "def index():\n    return 'hello'\n", encoding="utf-8"
    )
    (repo_path / "app" / "models.py").write_text(
        "class User:\n    pass\n", encoding="utf-8"
    )
    (repo_path / "app" / "utils.py").write_text(
        "def helper(x):\n    return x + 1\n", encoding="utf-8"
    )


def test_pipeline_accepts_affected_files_parameter(tmp_path: Path):
    """Verify AnalysisPipeline.run accepts affected_files parameter without error."""
    repo = tmp_path / "repo"
    _setup_sample_repo(repo)

    pipeline = AnalysisPipeline()
    result = pipeline.run(
        target_path=repo,
        affected_files={"app/views.py"},
    )
    assert result.status.value == "COMPLETED"
    assert len(result.files) == 3


def test_pipeline_selective_parsing_default_disabled(tmp_path: Path):
    """Verify selective parsing is disabled by default."""
    cfg = AnalysisConfig()
    assert cfg.enable_selective_parsing is False

    repo = tmp_path / "repo"
    _setup_sample_repo(repo)

    cache = InMemoryAnalysisCache()
    pipeline = AnalysisPipeline()

    result = pipeline.run(
        target_path=repo,
        analysis_config=cfg,
        cache=cache,
        affected_files={"app/views.py"},
    )
    assert result.status.value == "COMPLETED"
    assert len(result.files) == 3


def test_pipeline_selective_parsing_with_cache(tmp_path: Path):
    """Verify selective parsing retrieves unaffected files from L2 cache when enabled."""
    repo = tmp_path / "repo"
    _setup_sample_repo(repo)

    cache = InMemoryAnalysisCache()
    cfg = AnalysisConfig(enable_selective_parsing=True)
    pipeline = AnalysisPipeline()

    # Run 1: Cold run populates L2 cache
    res1 = pipeline.run(
        target_path=repo,
        analysis_config=cfg,
        cache=cache,
    )
    assert res1.status.value == "COMPLETED"

    # Verify L2 entries were populated in cache
    l2_entries = [k for (layer, k) in cache._store.keys() if layer == "L2"]
    assert len(l2_entries) >= 3

    # Run 2: Selective parsing with only app/views.py in affected_files
    res2 = pipeline.run(
        target_path=repo,
        analysis_config=cfg,
        cache=cache,
        affected_files={"app/views.py"},
    )
    assert res2.status.value == "COMPLETED"
    assert len(res2.files) == 3


def test_pipeline_selective_parsing_safe_fallback_on_miss(tmp_path: Path):
    """Verify selective parsing safely falls back to parsing if L2 cache entry is missing."""
    repo = tmp_path / "repo"
    _setup_sample_repo(repo)

    cache = InMemoryAnalysisCache()  # Empty cache
    cfg = AnalysisConfig(enable_selective_parsing=True)
    pipeline = AnalysisPipeline()

    # Even though cache is empty and unaffected files miss L2, it must safely parse all files
    res = pipeline.run(
        target_path=repo,
        analysis_config=cfg,
        cache=cache,
        affected_files={"app/views.py"},
    )
    assert res.status.value == "COMPLETED"
    assert len(res.files) == 3
