"""Integration tests for Phase 22 context-aware security intelligence and incremental hardening."""

from pathlib import Path
import pytest

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache
from analyzer.incremental.equivalence import EquivalenceChecker
from analyzer.models.errors import AnalysisCancelledError
from analyzer.models.evidence import SecurityEvidenceChain


@pytest.fixture
def dataflow_repo(tmp_path: Path):
    """Create a multi-file Python repository with cross-function data flow."""
    repo = tmp_path / "dataflow_repo"
    repo.mkdir()

    # Module 1: Sources and Views
    (repo / "views.py").write_text(
        "from db import execute_query\n\n"
        "def handle_request(req):\n"
        "    query = req.get('q')\n"
        "    return execute_query(query)\n",
        encoding="utf-8",
    )

    # Module 2: Sinks and DB
    (repo / "db.py").write_text(
        "import sqlite3\n\n"
        "def execute_query(sql):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(sql)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )

    # Module 3: Independent utility
    (repo / "utils.py").write_text(
        "def format_str(s):\n    return str(s).strip()\n",
        encoding="utf-8",
    )

    return repo


def test_phase22_cold_start_and_telemetry(dataflow_repo: Path, tmp_path: Path):
    """Verify Phase 22 cold-start incremental analysis populates caches and telemetry."""
    cache = InMemoryAnalysisCache()
    cfg = AnalysisConfig()
    pipeline = AnalysisPipeline()

    result = pipeline.run(
        target_path=dataflow_repo,
        analysis_config=cfg,
        mode="incremental",
        cache=cache,
    )

    assert result.status.value == "COMPLETED"
    assert result.call_graph_summary is not None
    inc_stats = result.call_graph_summary.get("incremental", {})
    assert inc_stats.get("files_discovered") == 3
    assert "taint_summary_hits" in inc_stats
    assert "composition_hits" in inc_stats


def test_phase22_warm_cache_fast_path(dataflow_repo: Path, tmp_path: Path):
    """Verify 100% cache hit fast-path on unmodified repository."""
    cache_dir = tmp_path / "cache"
    cache = DiskAnalysisCache(cache_root=cache_dir, repo_namespace_id="repo_fast")
    pipeline = AnalysisPipeline()

    # Run 1: Cold start
    res1 = pipeline.run(target_path=dataflow_repo, mode="incremental", cache=cache)
    assert res1.status.value == "COMPLETED"

    # Run 2: Unmodified warm run
    res2 = pipeline.run(target_path=dataflow_repo, mode="incremental", cache=cache)
    assert res2.status.value == "COMPLETED"

    inc2 = res2.call_graph_summary.get("incremental", {})
    assert inc2.get("hit_ratio") == 1.0
    assert inc2.get("files_reused") == 3
    assert inc2.get("files_reanalyzed") == 0


def test_phase22_warm_cache_equivalence(dataflow_repo: Path, tmp_path: Path):
    """Verify incremental and full analysis equivalence with Phase 22 verification."""
    cache = InMemoryAnalysisCache()
    pipeline = AnalysisPipeline()

    # Baseline run
    pipeline.run(target_path=dataflow_repo, mode="incremental", cache=cache)

    # Modify only utils.py (independent leaf module)
    (dataflow_repo / "utils.py").write_text(
        "def format_str(s):\n    # Updated doc\n    return str(s).strip().lower()\n",
        encoding="utf-8",
    )

    # Incremental run
    inc_res = pipeline.run(target_path=dataflow_repo, mode="incremental", cache=cache)

    # Fresh full run
    full_res = pipeline.run(target_path=dataflow_repo, mode="full")

    # Equivalence check
    eq = EquivalenceChecker.compare(full_res, inc_res, verify_contracts=True, verify_composition=True)
    assert eq.is_equivalent is True
    assert len(eq.discrepancies) == 0


def test_phase22_finding_identity_preservation(dataflow_repo: Path):
    """Verify finding identities are preserved with evidence chains enabled vs disabled."""
    pipeline = AnalysisPipeline()

    cfg_enabled = AnalysisConfig(enable_evidence_chains=True)
    res_enabled = pipeline.run(target_path=dataflow_repo, analysis_config=cfg_enabled)

    cfg_disabled = AnalysisConfig(enable_evidence_chains=False)
    res_disabled = pipeline.run(target_path=dataflow_repo, analysis_config=cfg_disabled)

    assert len(res_enabled.security_findings) == len(res_disabled.security_findings)
    assert len(res_enabled.architecture_findings) == len(res_disabled.architecture_findings)

    ids_enabled = {f.id for f in res_enabled.security_findings}
    ids_disabled = {f.id for f in res_disabled.security_findings}
    assert ids_enabled == ids_disabled


def test_phase22_determinism(dataflow_repo: Path):
    """Verify repeated runs produce byte-identical finding identities and evidence chains."""
    pipeline = AnalysisPipeline()

    res1 = pipeline.run(target_path=dataflow_repo)
    res2 = pipeline.run(target_path=dataflow_repo)

    f1 = sorted(res1.security_findings, key=lambda f: f.id)
    f2 = sorted(res2.security_findings, key=lambda f: f.id)

    assert len(f1) == len(f2)
    for a, b in zip(f1, f2):
        assert a.id == b.id
        assert a.rule_id == b.rule_id
        if "security_chain" in a.evidence and "security_chain" in b.evidence:
            chain_a = SecurityEvidenceChain.model_validate(a.evidence["security_chain"])
            chain_b = SecurityEvidenceChain.model_validate(b.evidence["security_chain"])
            assert chain_a.chain_hash == chain_b.chain_hash


def test_phase22_cooperative_cancellation(dataflow_repo: Path):
    """Verify cooperative cancellation check terminates analysis cleanly."""
    pipeline = AnalysisPipeline()

    with pytest.raises(AnalysisCancelledError):
        pipeline.run(
            target_path=dataflow_repo,
            is_cancelled=lambda: True,
        )
