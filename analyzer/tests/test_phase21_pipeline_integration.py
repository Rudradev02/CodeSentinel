"""Integration tests for Phase 21 incremental analysis pipeline and coordinator."""

import json
from pathlib import Path
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache
from analyzer.incremental.equivalence import EquivalenceChecker


class TestIncrementalPipelineIntegration:
    """Verifies end-to-end incremental pipeline orchestration."""

    @pytest.fixture
    def sample_repo(self, tmp_path):
        repo = tmp_path / "sample_repo"
        repo.mkdir()

        # Create two independent modules
        mod_a = repo / "mod_a.py"
        mod_a.write_text(
            "import os\n\ndef helper(x):\n    return x + 1\n",
            encoding="utf-8",
        )

        mod_b = repo / "mod_b.py"
        mod_b.write_text(
            "def compute(val):\n    return val * 2\n",
            encoding="utf-8",
        )

        return repo

    def test_incremental_cold_start_and_warm_hit(self, sample_repo, tmp_path):
        cache_dir = tmp_path / "cache"
        cache = DiskAnalysisCache(cache_root=cache_dir, repo_namespace_id="repo1")
        pipeline = AnalysisPipeline()

        # 1. Cold start incremental run
        res1 = pipeline.run(
            target_path=sample_repo,
            mode="incremental",
            cache=cache,
        )

        assert res1 is not None
        assert res1.call_graph_summary is not None
        inc1 = res1.call_graph_summary.get("incremental", {})
        assert inc1.get("files_discovered") == 2
        assert inc1.get("files_reused") == 0
        assert inc1.get("files_reanalyzed") == 2

        # 2. Warm run with no changes (100% cache hit)
        res2 = pipeline.run(
            target_path=sample_repo,
            mode="incremental",
            cache=cache,
        )

        assert res2 is not None
        inc2 = res2.call_graph_summary.get("incremental", {})
        assert inc2.get("hit_ratio") == 1.0
        assert inc2.get("files_reused") == 2
        assert inc2.get("files_reanalyzed") == 0

    def test_incremental_partial_edit_and_equivalence(self, sample_repo, tmp_path):
        cache_dir = tmp_path / "cache"
        cache = DiskAnalysisCache(cache_root=cache_dir, repo_namespace_id="repo2")
        pipeline = AnalysisPipeline()

        # Initial baseline run
        pipeline.run(target_path=sample_repo, mode="incremental", cache=cache)

        # Modify mod_b.py only
        (sample_repo / "mod_b.py").write_text(
            "def compute(val):\n    # Updated logic\n    return val * 3\n",
            encoding="utf-8",
        )

        # Incremental run
        inc_res = pipeline.run(target_path=sample_repo, mode="incremental", cache=cache)
        inc_stats = inc_res.call_graph_summary.get("incremental", {})

        # mod_a is reusable, mod_b is re-analyzed
        assert inc_stats.get("files_reanalyzed") >= 1

        # Run fresh full analysis on same modified state
        full_res = pipeline.run(target_path=sample_repo, mode="full")

        # Verify equivalence
        eq = EquivalenceChecker.compare(full_res, inc_res)
        assert eq.is_equivalent is True
        assert len(eq.discrepancies) == 0
