"""Tests for safe, read-only Git metadata extraction (Phase 9)."""

from pathlib import Path
import pytest

from analyzer.ingestion.git import get_git_metadata, _read_git_dir_directly


def test_git_metadata_non_git_directory(tmp_path):
    """Verify non-git directory safely returns is_git_repo=False."""
    meta = get_git_metadata(tmp_path)
    assert not meta.is_git_repo
    assert meta.commit_hash is None
    assert meta.branch is None
    assert meta.is_dirty is None


def test_git_metadata_on_current_repo():
    """Verify safe Git extraction on current CodeSentinel repository."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    if (repo_root / ".git").exists():
        meta = get_git_metadata(repo_root)
        assert meta.is_git_repo
        if meta.commit_hash:
            assert len(meta.commit_hash) == 40
        if meta.branch:
            assert meta.branch != ""


def test_read_git_dir_directly_synthetic_branch(tmp_path):
    """Verify direct file parsing of synthetic .git structure with named branch."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    head_file = git_dir / "HEAD"
    head_file.write_text("ref: refs/heads/feature/ci-pipeline\n", encoding="utf-8")

    refs_dir = git_dir / "refs" / "heads" / "feature"
    refs_dir.mkdir(parents=True)
    ref_file = refs_dir / "ci-pipeline"
    dummy_sha = "a" * 40
    ref_file.write_text(dummy_sha + "\n", encoding="utf-8")

    commit_hash, branch = _read_git_dir_directly(git_dir)
    assert branch == "ci-pipeline"
    assert commit_hash == dummy_sha


def test_read_git_dir_directly_detached_head(tmp_path):
    """Verify direct file parsing of detached HEAD containing commit hash."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    head_file = git_dir / "HEAD"
    dummy_sha = "b" * 40
    head_file.write_text(dummy_sha + "\n", encoding="utf-8")

    commit_hash, branch = _read_git_dir_directly(git_dir)
    assert commit_hash == dummy_sha
    assert branch == "HEAD (detached)"
