"""Tests for repository ingestion, path validation, and ignore rules."""

from pathlib import Path
import pytest

from analyzer.ingestion.discovery import count_lines, discover_repository_files, is_binary_file
from analyzer.ingestion.ignore import IgnoreEngine, IngestionConfig
from analyzer.ingestion.repository import validate_repository_path


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_validate_repository_path_success(sample_repo_path):
    validated = validate_repository_path(sample_repo_path)
    assert validated == sample_repo_path
    assert validated.is_dir()


def test_validate_repository_path_nonexistent(tmp_path):
    missing = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError):
        validate_repository_path(missing)


def test_validate_repository_path_file_not_dir(sample_repo_path):
    file_path = sample_repo_path / "requirements.txt"
    with pytest.raises(ValueError, match="must be a directory"):
        validate_repository_path(file_path)


def test_validate_repository_path_empty():
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_repository_path("")


def test_ignore_engine_defaults(sample_repo_path):
    ignorer = IgnoreEngine(sample_repo_path)
    assert ignorer.should_ignore("node_modules/react/index.js")
    assert ignorer.should_ignore(".git/config")
    assert ignorer.should_ignore("__pycache__/test.cpython-312.pyc")
    assert ignorer.should_ignore("dist/bundle.js")
    assert not ignorer.should_ignore("backend/app.py")


def test_ignore_engine_gitignore_and_sentinelignore(sample_repo_path):
    ignorer = IgnoreEngine(sample_repo_path)
    # ignored/ is in sample_project/.gitignore
    assert ignorer.should_ignore("ignored/ignored.py")
    assert ignorer.should_ignore("ignored/subfolder/file.py")
    # *.log in .gitignore
    assert ignorer.should_ignore("app.log")
    # temp_sentinel/ in .sentinelignore
    assert ignorer.should_ignore("temp_sentinel/cache.json")
    # Non-ignored file
    assert not ignorer.should_ignore("backend/services/user_service.py")


def test_discover_repository_files(sample_repo_path):
    files, manifests = discover_repository_files(sample_repo_path)
    rel_paths = {f.relative_path.replace("\\", "/") for f in files}

    # Verify discovered source files
    assert "backend/app.py" in rel_paths
    assert "backend/services/user_service.py" in rel_paths
    assert "backend/models/user.py" in rel_paths
    assert "frontend/App.tsx" in rel_paths
    assert "frontend/components/Button.tsx" in rel_paths
    assert "frontend/utils/api.ts" in rel_paths
    assert "broken.py" in rel_paths

    # Verify ignored files are NOT present
    assert "ignored/ignored.py" not in rel_paths

    # Verify manifests
    manifest_names = {m.name for m in manifests}
    assert "package.json" in manifest_names
    assert "requirements.txt" in manifest_names


def test_file_count_safety_limit(sample_repo_path):
    # Set limit to 2 files to verify limit enforcement
    cfg = IngestionConfig(max_files=2)
    with pytest.raises(RuntimeError, match="exceeds maximum file count"):
        discover_repository_files(sample_repo_path, config=cfg)
