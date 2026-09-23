"""Tests for Phase 14 repository configuration loading, validation, and hash determinism."""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from analyzer.config.file_loader import ConfigLoadError, load_repo_config
from analyzer.config.repo_config import RepoConfig


def test_repo_config_valid_defaults():
    """Empty dict or minimal dict initializes valid RepoConfig with proper defaults."""
    cfg = RepoConfig()
    assert cfg.version == 1
    assert cfg.analysis.enabled_rules is None
    assert cfg.analysis.disabled_rules == []
    assert cfg.reporting.format == "terminal"
    assert cfg.paths.exclude == []


def test_repo_config_validation_invalid_rule():
    """Rule ID not adhering to uppercase alphanumeric-hyphen pattern raises validation error."""
    with pytest.raises(ValidationError):
        RepoConfig(analysis={"disabled_rules": ["invalid_rule_with_lowercase"]})


def test_repo_config_validation_invalid_severity():
    """Invalid fail_on severity raises validation error."""
    with pytest.raises(ValidationError):
        RepoConfig(analysis={"fail_on": "SUPER_CRITICAL"})


def test_repo_config_validation_path_traversal():
    """Paths in paths.exclude containing '..' path traversal are rejected."""
    with pytest.raises(ValidationError) as excinfo:
        RepoConfig(paths={"exclude": ["../outside_repo/*"]})
    assert "traversal" in str(excinfo.value).lower()


def test_repo_config_hash_determinism():
    """SHA-256 config hash is deterministic and invariant to dictionary ordering."""
    c1 = RepoConfig(
        analysis={"god_module_loc": 450, "fail_on": "HIGH"},
        reporting={"format": "json"},
    )
    c2 = RepoConfig(
        reporting={"format": "json"},
        analysis={"fail_on": "HIGH", "god_module_loc": 450},
    )
    assert c1.compute_hash() == c2.compute_hash()
    assert len(c1.compute_hash()) == 64


def test_load_repo_config_yaml_discovery(tmp_path: Path):
    """load_repo_config automatically finds and parses .codesentinel.yml in target directory."""
    yml_file = tmp_path / ".codesentinel.yml"
    yml_file.write_text(
        """version: 1
analysis:
  god_module_loc: 600
  fail_on: MEDIUM
reporting:
  format: markdown
paths:
  exclude:
    - "legacy/**"
""",
        encoding="utf-8",
    )

    cfg, path, cfg_hash = load_repo_config(target_dir=str(tmp_path))
    assert cfg is not None
    assert path == str(yml_file.resolve())
    assert cfg.analysis.god_module_loc == 600
    assert cfg.analysis.fail_on == "MEDIUM"
    assert cfg.reporting.format == "markdown"
    assert cfg.paths.exclude == ["legacy/**"]
    assert cfg_hash == cfg.compute_hash()


def test_load_repo_config_json_discovery(tmp_path: Path):
    """load_repo_config discovers and parses .codesentinel.json when no YAML is present."""
    json_file = tmp_path / ".codesentinel.json"
    json_file.write_text(
        json.dumps({
            "version": 1,
            "analysis": {"centrality_threshold": 0.4},
            "reporting": {"format": "html"},
        }),
        encoding="utf-8",
    )

    cfg, path, cfg_hash = load_repo_config(target_dir=str(tmp_path))
    assert cfg is not None
    assert path == str(json_file.resolve())
    assert cfg.analysis.centrality_threshold == 0.4
    assert cfg.reporting.format == "html"
    assert cfg_hash is not None


def test_load_repo_config_explicit_path(tmp_path: Path):
    """load_repo_config loads config from an explicitly specified file path outside target dir."""
    custom_cfg = tmp_path / "custom.yml"
    custom_cfg.write_text(
        """version: 1
analysis:
  max_taint_depth: 30
""",
        encoding="utf-8",
    )

    target_dir = tmp_path / "codebase"
    target_dir.mkdir()

    cfg, path, cfg_hash = load_repo_config(target_dir=str(target_dir), explicit_config_path=str(custom_cfg))
    assert cfg is not None
    assert path == str(custom_cfg.resolve())
    assert cfg.analysis.max_taint_depth == 30


def test_load_repo_config_explicit_not_found(tmp_path: Path):
    """Specifying a non-existent explicit config path raises ConfigLoadError."""
    with pytest.raises(ConfigLoadError) as exc:
        load_repo_config(target_dir=str(tmp_path), explicit_config_path=str(tmp_path / "does_not_exist.yml"))
    assert "not found" in str(exc.value).lower()


def test_load_repo_config_malformed_yaml(tmp_path: Path):
    """Malformed YAML raises ConfigLoadError."""
    bad_yml = tmp_path / ".codesentinel.yml"
    bad_yml.write_text("version: 1\n  invalid_indentation: [unclosed", encoding="utf-8")

    with pytest.raises(ConfigLoadError) as exc:
        load_repo_config(target_dir=str(tmp_path))
    assert "failed to parse" in str(exc.value).lower()


def test_load_repo_config_none_found(tmp_path: Path):
    """When no config file exists, load_repo_config returns (None, None, None)."""
    cfg, path, cfg_hash = load_repo_config(target_dir=str(tmp_path))
    assert cfg is None
    assert path is None
    assert cfg_hash is None
