"""Phase 6: Python dependency resolution tests.

Tests cover:
- Absolute imports (import foo.bar)
- Submodule imports (from foo import bar where foo/bar.py exists)
- Relative imports (from . import x, from .foo import bar, from ..foo import bar)
- Standard package layout vs src/ layout
- Category classification (LOCAL, STDLIB, EXTERNAL, UNRESOLVED)
- Unresolved relative imports never become EXTERNAL
"""

import pytest
from pathlib import Path
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile
from analyzer.models.graph import ImportType


def _make_file(rel_path: str, lang: str = "PYTHON") -> DiscoveredFileMetadata:
    """Create a minimal DiscoveredFileMetadata for testing."""
    return DiscoveredFileMetadata(
        path=f"/repo/{rel_path}",
        relative_path=rel_path,
        extension=Path(rel_path).suffix,
        language=lang,
        size_bytes=100,
        line_count=10,
    )


def _make_import(source_module: str, is_relative: bool = False, imported_names: list = None) -> ImportStatement:
    """Create a minimal ImportStatement for testing."""
    return ImportStatement(
        source_module=source_module,
        imported_names=imported_names or [],
        import_type=ImportType.STATIC,
        line_number=1,
        is_relative=is_relative,
        dependency_category=ImportCategory.UNRESOLVED,
    )


class TestPythonAbsoluteImports:
    """Test absolute Python import resolution."""

    def test_absolute_import_resolves_to_module_file(self):
        """import app.services.user_service resolves to app/services/user_service.py"""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/services/__init__.py"),
            _make_file("app/services/user_service.py"),
            _make_file("app/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("app.services.user_service")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "app/services/user_service.py"

    def test_absolute_import_resolves_to_package_init(self):
        """import app.services resolves to app/services/__init__.py"""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/services/__init__.py"),
            _make_file("app/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("app.services")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "app/services/__init__.py"

    def test_absolute_import_unresolved(self):
        """import nonexistent_module classifies as EXTERNAL (no local prefix match)."""
        files = [_make_file("app/main.py")]
        resolver = DependencyResolver(files)
        imp = _make_import("nonexistent_module")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.EXTERNAL


class TestPythonSubmoduleImports:
    """Test from-import submodule resolution."""

    def test_from_foo_import_bar_resolves_submodule_file(self):
        """from app.services import user_service -> app/services/user_service.py"""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/services/__init__.py"),
            _make_file("app/services/user_service.py"),
            _make_file("app/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("app.services", imported_names=["user_service"])
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        # Should resolve to either the package init or the submodule file
        assert imp.resolved_path in (
            "app/services/__init__.py",
            "app/services/user_service.py",
        )


class TestPythonRelativeImports:
    """Test relative Python import resolution."""

    def test_single_dot_import(self):
        """from . import utils resolves within same directory."""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/utils.py"),
            _make_file("app/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import(".utils", is_relative=True)
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "app/utils.py"

    def test_double_dot_import(self):
        """from ..models import user resolves from parent directory."""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/models/__init__.py"),
            _make_file("app/models/user.py"),
            _make_file("app/services/__init__.py"),
            _make_file("app/services/user_service.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("..models.user", is_relative=True)
        resolver.resolve_import("app/services/user_service.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "app/models/user.py"

    def test_relative_import_unresolved_stays_unresolved(self):
        """Relative imports that fail resolution must be UNRESOLVED, never EXTERNAL."""
        files = [
            _make_file("app/__init__.py"),
            _make_file("app/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import(".nonexistent", is_relative=True)
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.UNRESOLVED
        assert imp.dependency_category != ImportCategory.EXTERNAL

    def test_from_dot_import_name(self):
        """from . import x where x.py exists in same directory."""
        files = [
            _make_file("pkg/__init__.py"),
            _make_file("pkg/x.py"),
            _make_file("pkg/y.py"),
        ]
        resolver = DependencyResolver(files)
        # The source_module for "from . import x" is "." and imported_names=["x"]
        imp = _make_import(".", is_relative=True, imported_names=["x"])
        resolver.resolve_import("pkg/y.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL

    def test_relative_from_dot_foo_import_bar(self):
        """from .foo import bar where foo/bar.py exists."""
        files = [
            _make_file("pkg/__init__.py"),
            _make_file("pkg/foo/__init__.py"),
            _make_file("pkg/foo/bar.py"),
            _make_file("pkg/main.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import(".foo", is_relative=True, imported_names=["bar"])
        resolver.resolve_import("pkg/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL


class TestPythonSrcLayout:
    """Test Python src/ layout resolution."""

    def test_src_layout_import(self):
        """import mypkg.util resolves to src/mypkg/util.py"""
        files = [
            _make_file("src/mypkg/__init__.py"),
            _make_file("src/mypkg/util.py"),
            _make_file("tests/test_util.py"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("mypkg.util")
        resolver.resolve_import("tests/test_util.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/mypkg/util.py"


class TestPythonStdlib:
    """Test Python standard library detection."""

    def test_stdlib_os(self):
        files = [_make_file("app/main.py")]
        resolver = DependencyResolver(files)
        imp = _make_import("os")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        assert imp.dependency_category == ImportCategory.STDLIB

    def test_stdlib_json(self):
        files = [_make_file("app/main.py")]
        resolver = DependencyResolver(files)
        imp = _make_import("json")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        assert imp.dependency_category == ImportCategory.STDLIB

    def test_stdlib_nested(self):
        """import os.path should be classified as STDLIB."""
        files = [_make_file("app/main.py")]
        resolver = DependencyResolver(files)
        imp = _make_import("os.path")
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        assert imp.dependency_category == ImportCategory.STDLIB


class TestPythonDiagnostics:
    """Test dependency diagnostic generation for Python resolution failures."""

    def test_unresolved_relative_generates_diagnostic(self):
        files = [_make_file("app/main.py")]
        resolver = DependencyResolver(files)
        imp = _make_import(".missing", is_relative=True)
        resolver.resolve_import("app/main.py", "PYTHON", imp)
        
        assert imp.dependency_category == ImportCategory.UNRESOLVED
        assert len(resolver.diagnostics) >= 1
        diag = resolver.diagnostics[0]
        assert diag.diagnostic_type == "UNRESOLVED_RELATIVE_IMPORT"
        assert diag.assigned_category == "UNRESOLVED"
