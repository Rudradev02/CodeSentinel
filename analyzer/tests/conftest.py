"""Shared pytest fixtures for analyzer test suite."""

from pathlib import Path
import pytest


@pytest.fixture
def sample_repo_path() -> Path:
    """Fixture providing Path to the sample test repository."""
    return Path(__file__).parent / "fixtures" / "sample_project"
