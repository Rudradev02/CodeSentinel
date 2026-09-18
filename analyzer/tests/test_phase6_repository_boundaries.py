"""Phase 6: Repository boundary enforcement tests.

Tests cover:
- Exclusion of vendor/dependency directories (node_modules, .venv, __pycache__, dist, build)
- No traversal of symlinks outside repository root (followlinks=False enforcement)
"""

import os
import pytest
import tempfile
from pathlib import Path
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.ingestion.ignore import IgnoreEngine, DEFAULT_EXCLUDED_DIRS


class TestDirectoryExclusion:
    """Verify vendor/dependency directory exclusion."""

    def test_node_modules_excluded(self, tmp_path):
        """node_modules directory should be completely excluded."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.js").write_text("console.log('hello');")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "react" / "index.js").parent.mkdir(parents=True)
        (tmp_path / "node_modules" / "react" / "index.js").write_text("module.exports = {};")
        
        files, _ = discover_repository_files(tmp_path)
        rel_paths = [f.relative_path for f in files]
        
        assert "src/app.js" in rel_paths
        assert not any("node_modules" in p for p in rel_paths)

    def test_venv_excluded(self, tmp_path):
        """.venv directory should be excluded."""
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / ".venv" / "lib").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "site.py").write_text("# site packages")
        
        files, _ = discover_repository_files(tmp_path)
        rel_paths = [f.relative_path for f in files]
        
        assert "app.py" in rel_paths
        assert not any(".venv" in p for p in rel_paths)

    def test_pycache_excluded(self, tmp_path):
        """__pycache__ directory should be excluded."""
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "app.cpython-311.pyc").write_bytes(b"\x00")
        
        files, _ = discover_repository_files(tmp_path)
        rel_paths = [f.relative_path for f in files]
        
        assert not any("__pycache__" in p for p in rel_paths)

    def test_dist_and_build_excluded(self, tmp_path):
        """dist and build directories should be excluded."""
        (tmp_path / "src" / "app.ts").parent.mkdir()
        (tmp_path / "src" / "app.ts").write_text("const x = 1;")
        (tmp_path / "dist").mkdir()
        (tmp_path / "dist" / "app.js").write_text("var x = 1;")
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "app.js").write_text("var x = 1;")
        
        files, _ = discover_repository_files(tmp_path)
        rel_paths = [f.relative_path for f in files]
        
        assert "src/app.ts" in rel_paths
        assert not any("dist" in p for p in rel_paths)
        assert not any("build" in p for p in rel_paths)

    def test_all_default_excluded_dirs_are_excluded(self, tmp_path):
        """All directories in DEFAULT_EXCLUDED_DIRS should be excluded."""
        (tmp_path / "app.py").write_text("print('hello')")
        
        for dirname in DEFAULT_EXCLUDED_DIRS:
            dir_path = tmp_path / dirname
            dir_path.mkdir(exist_ok=True)
            (dir_path / "test.py").write_text("# excluded")
        
        files, _ = discover_repository_files(tmp_path)
        rel_paths = [f.relative_path for f in files]
        
        # Only app.py should be discovered
        assert rel_paths == ["app.py"]


class TestSymlinkBoundary:
    """Verify symlink boundary enforcement."""

    @pytest.mark.skipif(os.name == "nt", reason="Symlinks may require admin on Windows")
    def test_symlinks_outside_repo_not_followed(self, tmp_path):
        """Symlinks pointing outside repository root should not be traversed."""
        # Create an external directory
        external_dir = tmp_path / "external_secret"
        external_dir.mkdir()
        (external_dir / "secret.py").write_text("SECRET = 'hunter2'")
        
        # Create the repo directory
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("print('hello')")
        
        # Create symlink from repo to external
        try:
            (repo_dir / "leaked").symlink_to(external_dir)
        except OSError:
            pytest.skip("Cannot create symlink")
        
        files, _ = discover_repository_files(repo_dir)
        rel_paths = [f.relative_path for f in files]
        
        assert "app.py" in rel_paths
        assert not any("secret" in p for p in rel_paths)
        assert not any("leaked" in p for p in rel_paths)


class TestIgnoreEngineComprehensive:
    """Verify comprehensive exclusion rules in IgnoreEngine."""

    def test_ignore_engine_rejects_excluded_dirs(self, tmp_path):
        engine = IgnoreEngine(tmp_path)
        for dirname in DEFAULT_EXCLUDED_DIRS:
            assert engine.should_ignore(dirname, is_dir=True), f"{dirname} should be ignored"

    def test_ignore_engine_rejects_nested_excluded_dirs(self, tmp_path):
        engine = IgnoreEngine(tmp_path)
        # Even nested paths containing excluded dir names should be ignored
        assert engine.should_ignore("src/node_modules/react/index.js", is_dir=False)
        assert engine.should_ignore("app/__pycache__/module.pyc", is_dir=False)

    def test_ignore_engine_allows_normal_files(self, tmp_path):
        engine = IgnoreEngine(tmp_path)
        assert not engine.should_ignore("src/app.py", is_dir=False)
        assert not engine.should_ignore("frontend/App.tsx", is_dir=False)
