"""Tests for Phase 14 CLI extensions, --config flag, and new output formats."""

import json
from pathlib import Path
from analyzer.cli.main import main


def test_cli_analyze_format_markdown_output_file(tmp_path: Path):
    """CLI writes markdown report to specified output file."""
    out_file = tmp_path / "report.md"
    exit_code = main([
        "analyze",
        "analyzer/tests/fixtures/sample_project",
        "--format",
        "markdown",
        "-o",
        str(out_file),
    ])
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "CodeSentinel Static Analysis Report" in content


def test_cli_analyze_format_html_output_file(tmp_path: Path):
    """CLI writes standalone HTML report to specified output file."""
    out_file = tmp_path / "report.html"
    exit_code = main([
        "analyze",
        "analyzer/tests/fixtures/sample_project",
        "--format",
        "html",
        "-o",
        str(out_file),
    ])
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "CodeSentinel Report:" in content


def test_cli_analyze_format_junit_output_file(tmp_path: Path):
    """CLI writes JUnit XML report to specified output file."""
    out_file = tmp_path / "junit.xml"
    exit_code = main([
        "analyze",
        "analyzer/tests/fixtures/sample_project",
        "--format",
        "junit",
        "-o",
        str(out_file),
    ])
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "<testsuites" in content


def test_cli_analyze_format_gitlab_output_file(tmp_path: Path):
    """CLI writes GitLab Code Quality JSON report to specified output file."""
    out_file = tmp_path / "gl-code-quality-report.json"
    exit_code = main([
        "analyze",
        "analyzer/tests/fixtures/sample_project",
        "--format",
        "gitlab",
        "-o",
        str(out_file),
    ])
    assert exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)


def test_cli_explicit_config_flag(tmp_path: Path):
    """CLI honors -c / --config explicit path flag."""
    cfg_file = tmp_path / "custom_config.yml"
    out_file = tmp_path / "report.md"
    cfg_file.write_text(
        f"""version: 1
reporting:
  format: markdown
  output_file: "{str(out_file).replace('\\', '/')}"
""",
        encoding="utf-8",
    )

    exit_code = main([
        "analyze",
        "analyzer/tests/fixtures/sample_project",
        "-c",
        str(cfg_file),
    ])
    assert exit_code == 0
    assert out_file.is_file()
    assert "CodeSentinel Static Analysis Report" in out_file.read_text(encoding="utf-8")


def test_cli_compare_format_markdown(tmp_path: Path):
    """CLI compare subcommand produces differential markdown output."""
    base_json = tmp_path / "base.json"
    curr_json = tmp_path / "curr.json"
    diff_md = tmp_path / "diff.md"

    # Generate current analysis JSON
    main(["analyze", "analyzer/tests/fixtures/sample_project", "--format", "json", "-o", str(base_json)])
    main(["analyze", "analyzer/tests/fixtures/sample_project", "--format", "json", "-o", str(curr_json)])

    exit_code = main([
        "compare",
        str(base_json),
        str(curr_json),
        "--format",
        "markdown",
        "-o",
        str(diff_md),
    ])
    assert exit_code == 0
    assert diff_md.is_file()
    content = diff_md.read_text(encoding="utf-8")
    assert "CodeSentinel Differential Regression Report" in content

