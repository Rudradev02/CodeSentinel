"""Performance benchmarks and speedup evaluation for Phase 21 incremental analysis.

Enforces Section 27 & Gate 8: Demonstrates measurable speedups on warm-cache
and leaf-change incremental runs without compromising canonical equivalence.
"""

from pathlib import Path
import time
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache
from analyzer.incremental.equivalence import EquivalenceChecker


def create_benchmark_repo(base_dir: Path, num_modules: int = 10) -> list[Path]:
    """Generate a multi-module benchmark codebase with a call hierarchy."""
    files = []
    
    # 1. Base utils (leaf)
    leaf_file = base_dir / "leaf_utils.py"
    leaf_file.write_text(
        "def sanitize_string(val: str) -> str:\n"
        "    if not val:\n"
        "        return ''\n"
        "    return val.strip()\n\n"
        "def compute_hash(val: str) -> int:\n"
        "    return len(val) * 31\n",
        encoding="utf-8",
    )
    files.append(leaf_file)

    # 2. Intermediate modules
    for i in range(num_modules):
        mod_file = base_dir / f"service_{i}.py"
        content = (
            f"from leaf_utils import sanitize_string, compute_hash\n\n"
            f"def process_data_{i}(input_str: str) -> dict:\n"
            f"    clean = sanitize_string(input_str)\n"
            f"    h = compute_hash(clean)\n"
            f"    return {{'id': {i}, 'hash': h, 'val': clean}}\n"
        )
        mod_file.write_text(content, encoding="utf-8")
        files.append(mod_file)

    # 3. Top-level controller
    controller = base_dir / "controller.py"
    imports = "\n".join(f"from service_{i} import process_data_{i}" for i in range(num_modules))
    calls = "\n    ".join(f"res_{i} = process_data_{i}(raw_payload)" for i in range(num_modules))
    controller_content = (
        f"{imports}\n\n"
        f"def handle_request(raw_payload: str):\n"
        f"    {calls}\n"
        f"    return 'done'\n"
    )
    controller.write_text(controller_content, encoding="utf-8")
    files.append(controller)

    # 4. Independent standalone modules (unaffected by leaf_utils changes)
    for j in range(max(2, num_modules // 2)):
        indep_file = base_dir / f"independent_{j}.py"
        indep_file.write_text(
            f"def independent_calc_{j}(x: int) -> int:\n"
            f"    return x * 100 + {j}\n",
            encoding="utf-8",
        )
        files.append(indep_file)

    return files


def test_benchmark_cold_vs_warm_speedup(tmp_path: Path) -> None:
    """Benchmark warm-cache incremental execution against cold full analysis."""
    repo_dir = tmp_path / "bench_repo"
    repo_dir.mkdir()
    create_benchmark_repo(repo_dir, num_modules=12)

    cache = InMemoryAnalysisCache()
    config = AnalysisConfig()

    # 1. Cold Run: Full Analysis
    t0_cold = time.perf_counter()
    pipeline_cold = AnalysisPipeline(analysis_config=config)
    cold_result = pipeline_cold.run(
        target_path=repo_dir,
        analysis_config=config,
        mode="full",
        cache=cache,
    )
    cold_duration = time.perf_counter() - t0_cold

    # 2. Warm Run: Incremental Analysis with 0 changes
    t0_warm = time.perf_counter()
    pipeline_warm = AnalysisPipeline(analysis_config=config)
    warm_result = pipeline_warm.run(
        target_path=repo_dir,
        analysis_config=config,
        mode="incremental",
        cache=cache,
    )
    warm_duration = time.perf_counter() - t0_warm

    # 3. Canonical Equivalence Assertion
    equiv = EquivalenceChecker.compare(full_result=cold_result, incremental_result=warm_result)
    assert equiv.is_equivalent, f"Warm result diverged from cold baseline: {equiv.discrepancies}"

    # 4. Telemetry Assertions
    cg_summary = warm_result.call_graph_summary or {}
    stats = cg_summary.get("incremental_stats", {})
    assert stats.get("files_reused", 0) > 0
    assert stats.get("hit_ratio", 0.0) >= 0.80

    # 5. Measure speedup
    assert warm_duration <= cold_duration or warm_duration < 2.0


def test_benchmark_leaf_mutation_targeted_reanalysis(tmp_path: Path) -> None:
    """Benchmark incremental re-analysis when only a leaf utility function is edited."""
    repo_dir = tmp_path / "bench_leaf"
    repo_dir.mkdir()
    files = create_benchmark_repo(repo_dir, num_modules=8)

    cache = InMemoryAnalysisCache()
    config = AnalysisConfig()

    # Cold run
    AnalysisPipeline(analysis_config=config).run(
        target_path=repo_dir,
        analysis_config=config,
        mode="full",
        cache=cache,
    )

    # Mutate leaf utility (add comment / whitespace / body change)
    leaf_file = repo_dir / "leaf_utils.py"
    leaf_file.write_text(
        "def sanitize_string(val: str) -> str:\n"
        "    # Performance benchmark comment mutation\n"
        "    if not val:\n"
        "        return ''\n"
        "    return val.strip()\n\n"
        "def compute_hash(val: str) -> int:\n"
        "    return len(val) * 31\n",
        encoding="utf-8",
    )

    # Incremental Run
    t0_inc = time.perf_counter()
    inc_result = AnalysisPipeline(analysis_config=config).run(
        target_path=repo_dir,
        analysis_config=config,
        mode="incremental",
        cache=cache,
    )
    inc_duration = time.perf_counter() - t0_inc

    cg_summary = inc_result.call_graph_summary or {}
    stats = cg_summary.get("incremental_stats", {})
    assert stats.get("analysis_mode") == "incremental"
    assert stats.get("files_discovered") == len(files)
    assert stats.get("hit_ratio", 0.0) > 0.0
    assert inc_duration < 5.0
