"""Unit and integration tests for Phase 21 CLI options and cache administration."""

import io
from pathlib import Path
import sys
import tempfile
import pytest

from analyzer.cli.main import main, build_parser


def test_cli_help_includes_incremental_options(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that codesentinel analyze --help exposes Phase 21 options."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["analyze", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--incremental" in captured.out
    assert "--no-cache" in captured.out
    assert "--cache-dir" in captured.out
    assert "--clear-cache" in captured.out
    assert "--cache-stats" in captured.out
    assert "--verify-equivalence" in captured.out


def test_cli_clear_cache(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that --clear-cache deletes cached artifacts and exits 0."""
    cache_dir = tmp_path / ".codesentinel_cache"
    cache_dir.mkdir(parents=True)
    dummy_file = cache_dir / "dummy.json"
    dummy_file.write_text("{}", encoding="utf-8")
    assert dummy_file.exists()

    code = main(["analyze", str(tmp_path), "--clear-cache"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Analysis cache cleared" in captured.out
    assert not dummy_file.exists()


def test_cli_custom_cache_dir_and_clear(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify --cache-dir with --clear-cache works on custom directory."""
    custom_cache = tmp_path / "custom_cache"
    custom_cache.mkdir(parents=True)
    dummy = custom_cache / "artifact.json"
    dummy.write_text("{}", encoding="utf-8")

    code = main(["analyze", str(tmp_path), "--cache-dir", str(custom_cache), "--clear-cache"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Analysis cache cleared" in captured.out
    assert not dummy.exists()


def test_cli_invalid_path(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify operational error on non-existent path."""
    code = main(["analyze", "non_existent_dir_12345"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Operational Error" in captured.err or "Error" in captured.err


def test_cli_full_analysis_default(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify standard analyze defaults to full and generates cache entries."""
    src = tmp_path / "app.py"
    src.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

    code = main(["analyze", str(tmp_path), "--format", "terminal"])
    assert code == 0
    captured = capsys.readouterr()
    assert "CODESENTINEL REPOSITORY STATIC ANALYSIS REPORT" in captured.out

    cache_dir = tmp_path / ".codesentinel_cache"
    assert cache_dir.exists()
    # Cache files should have been populated
    cache_files = list(cache_dir.glob("*.json"))
    assert len(cache_files) > 0


def test_cli_no_cache_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify --no-cache bypasses writing cache artifacts to disk."""
    src = tmp_path / "service.py"
    src.write_text("def compute():\n    return 42\n", encoding="utf-8")

    custom_cache = tmp_path / "empty_cache"
    code = main(["analyze", str(tmp_path), "--no-cache", "--cache-dir", str(custom_cache)])
    assert code == 0
    # Custom cache should not have been created or populated
    if custom_cache.exists():
        assert len(list(custom_cache.glob("*.json"))) == 0


def test_cli_incremental_and_cache_stats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify incremental analysis with --cache-stats outputs telemetry table."""
    src = tmp_path / "mod.py"
    src.write_text("def ping():\n    return 'pong'\n", encoding="utf-8")

    # Run 1: Cold run to populate cache
    code1 = main(["analyze", str(tmp_path), "--cache-stats"])
    assert code1 == 0
    out1 = capsys.readouterr().out
    assert "CODESENTINEL INCREMENTAL ANALYSIS & CACHE TELEMETRY" in out1

    # Run 2: Incremental run with cache hits
    code2 = main(["analyze", str(tmp_path), "--incremental", "--cache-stats"])
    assert code2 == 0
    out2 = capsys.readouterr().out
    assert "CODESENTINEL INCREMENTAL ANALYSIS & CACHE TELEMETRY" in out2
    assert "Files Reused (Validated)" in out2


def test_cli_verify_equivalence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify --verify-equivalence executes both pipelines and asserts equivalence."""
    src = tmp_path / "util.py"
    src.write_text(
        "import os\n"
        "def run_cmd(user_input):\n"
        "    os.system(user_input)\n",
        encoding="utf-8",
    )

    code = main(["analyze", str(tmp_path), "--verify-equivalence"])
    assert code == 0
