"""Multi-run determinism verification tests for Phase 21.

Enforces Gate 6: The analyzer MUST produce identical canonical output across
repeated incremental and full executions for identical repository content,
configuration, and validated cache state.
"""

from pathlib import Path
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache
from analyzer.incremental.equivalence import EquivalenceChecker


def test_five_run_incremental_determinism(tmp_path: Path) -> None:
    """Execute 5 consecutive incremental runs on the same repository and verify 100% bitwise/canonical determinism."""
    # Setup test repository
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    
    file_a = pkg / "a.py"
    file_a.write_text(
        "def compute(x):\n"
        "    if x > 10:\n"
        "        return x * 2\n"
        "    return x + 1\n",
        encoding="utf-8",
    )
    
    file_b = pkg / "b.py"
    file_b.write_text(
        "from pkg.a import compute\n"
        "import os\n"
        "def run(val):\n"
        "    res = compute(val)\n"
        "    os.system(f'echo {res}')\n",
        encoding="utf-8",
    )

    config = AnalysisConfig()
    cache = InMemoryAnalysisCache()

    # Initial Run (Run 0): Full warm-up
    pipeline = AnalysisPipeline(analysis_config=config)
    baseline_result = pipeline.run(
        target_path=tmp_path,
        analysis_config=config,
        mode="full",
        cache=cache,
    )
    baseline_dump = baseline_result.model_dump(
        mode="json",
        exclude={"id", "metadata", "created_at"},
    )

    # 5 Consecutive Incremental Runs without changes
    for run_idx in range(1, 6):
        run_pipeline = AnalysisPipeline(analysis_config=config)
        inc_result = run_pipeline.run(
            target_path=tmp_path,
            analysis_config=config,
            mode="incremental",
            cache=cache,
        )

        equiv = EquivalenceChecker.compare(full_result=baseline_result, incremental_result=inc_result)
        assert equiv.is_equivalent, f"Run {run_idx} failed equivalence: {equiv.discrepancies}"

        run_dump = inc_result.model_dump(
            mode="json",
            exclude={"id", "metadata", "created_at"},
        )

        # Assert findings identity determinism
        baseline_finding_ids = [f["id"] for f in baseline_dump.get("security_findings", [])]
        run_finding_ids = [f["id"] for f in run_dump.get("security_findings", [])]
        assert baseline_finding_ids == run_finding_ids, f"Run {run_idx} finding IDs differed: {run_finding_ids} vs {baseline_finding_ids}"

        # Assert summary metrics determinism
        assert baseline_dump["security_summary"] == run_dump["security_summary"]
        assert baseline_dump["architecture_summary"] == run_dump["architecture_summary"]


def test_deterministic_serialization_with_disk_cache(tmp_path: Path) -> None:
    """Verify determinism across disk cache re-loads."""
    src = tmp_path / "main.py"
    src.write_text(
        "import subprocess\n"
        "def execute_task(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n",
        encoding="utf-8",
    )

    cache_dir = tmp_path / ".cache"
    config = AnalysisConfig()

    # Run 1: Cold run saving to disk
    cache1 = DiskAnalysisCache(cache_root=cache_dir, repo_namespace_id="test_repo")
    res1 = AnalysisPipeline(analysis_config=config).run(
        target_path=tmp_path,
        analysis_config=config,
        mode="full",
        cache=cache1,
    )

    # Run 2: Incremental run reading from disk
    cache2 = DiskAnalysisCache(cache_root=cache_dir, repo_namespace_id="test_repo")
    res2 = AnalysisPipeline(analysis_config=config).run(
        target_path=tmp_path,
        analysis_config=config,
        mode="incremental",
        cache=cache2,
    )

    equiv = EquivalenceChecker.compare(full_result=res1, incremental_result=res2)
    assert equiv.is_equivalent
    assert len(res1.security_findings) == len(res2.security_findings)
    if res1.security_findings:
        assert res1.security_findings[0].id == res2.security_findings[0].id
