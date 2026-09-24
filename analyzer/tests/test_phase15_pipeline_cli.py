"""Tests for Phase 15 Workstream 15.8: Pipeline Integration and CLI Options."""

import os
from pathlib import Path
import tempfile
import pytest

from analyzer.cli.main import build_parser
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_pipeline_interprocedural_integration():
    """Verify AnalysisPipeline runs CALL_GRAPH and INTER_PROCEDURAL stages and populates call_graph_summary."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "utils").mkdir()

        db_py = root / "utils" / "db.py"
        db_py.write_text(
            "def build_query(user_input):\n"
            "    return f'SELECT * FROM users WHERE id = {user_input}'\n",
            encoding="utf-8",
        )

        views_py = root / "views.py"
        views_py.write_text(
            "from utils.db import build_query\n"
            "def handle_request(request):\n"
            "    user_id = request.args['id']\n"
            "    query = build_query(user_id)\n"
            "    cursor.execute(query)\n",
            encoding="utf-8",
        )

        stages_reported: list[tuple[str, int]] = []

        def progress_cb(stage: str, pct: int, msg: str) -> None:
            stages_reported.append((stage, pct))

        pipeline = AnalysisPipeline()
        result = pipeline.run(
            target_path=root,
            on_progress=progress_cb,
        )

        stage_names = [s[0] for s in stages_reported]
        assert "CALL_GRAPH" in stage_names
        assert "INTER_PROCEDURAL" in stage_names

        assert result.call_graph_summary is not None
        assert result.call_graph_summary["total_functions"] >= 2
        assert result.call_graph_summary["total_call_edges"] >= 1
        assert result.call_graph_summary["interprocedural_findings_count"] >= 1

        sec_rule_ids = [f.rule_id for f in result.security_findings]
        assert "SEC-PY-011" in sec_rule_ids


def test_pipeline_disable_interprocedural():
    """Verify --disable-interprocedural skips call graph construction and yields null summary."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        test_py = root / "test.py"
        test_py.write_text("def foo(x): return x\n", encoding="utf-8")

        stages_reported: list[str] = []

        def progress_cb(stage: str, pct: int, msg: str) -> None:
            stages_reported.append(stage)

        config = AnalysisConfig(disable_interprocedural=True)
        pipeline = AnalysisPipeline()
        result = pipeline.run(
            target_path=root,
            analysis_config=config,
            on_progress=progress_cb,
        )

        assert "CALL_GRAPH" not in stages_reported
        assert "INTER_PROCEDURAL" not in stages_reported
        assert result.call_graph_summary is None


def test_cli_parser_phase15_arguments():
    """Verify CLI parser accepts --max-call-depth and --disable-interprocedural."""
    parser = build_parser()
    args = parser.parse_args([
        "analyze",
        ".",
        "--max-call-depth", "8",
        "--disable-interprocedural",
    ])
    assert args.max_call_depth == 8
    assert args.disable_interprocedural is True
