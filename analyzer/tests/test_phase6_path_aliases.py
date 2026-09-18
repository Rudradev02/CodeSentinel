"""Phase 6: Path alias resolution tests via tsconfig.json / jsconfig.json.

Tests cover:
- Parse tsconfig.json with baseUrl and paths ("@/*" -> "src/*")
- Successfully resolve aliased imports to repository files
- Unresolvable alias path generates UNRESOLVED with diagnostic
"""

import json
import pytest
import tempfile
from pathlib import Path
from analyzer.dependencies.resolver import DependencyResolver, TsConfigResolver
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement
from analyzer.models.graph import ImportType


def _make_file(rel_path: str, lang: str = None) -> DiscoveredFileMetadata:
    ext = Path(rel_path).suffix
    if lang is None:
        lang = "TYPESCRIPT" if ext in (".ts", ".tsx") else "JAVASCRIPT"
    return DiscoveredFileMetadata(
        path=f"/repo/{rel_path}",
        relative_path=rel_path,
        extension=ext,
        language=lang,
        size_bytes=100,
        line_count=10,
    )


def _make_import(source_module: str, is_relative: bool = False) -> ImportStatement:
    return ImportStatement(
        source_module=source_module,
        imported_names=[],
        import_type=ImportType.STATIC,
        line_number=1,
        is_relative=is_relative,
        dependency_category=ImportCategory.UNRESOLVED,
    )


class TestTsConfigParsing:
    """Test TsConfigResolver parsing."""

    def test_loads_tsconfig_with_paths(self, tmp_path):
        """TsConfigResolver parses tsconfig.json with baseUrl and paths."""
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@/*": ["src/*"],
                    "@components/*": ["src/components/*"],
                }
            }
        }
        (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig))
        
        resolver = TsConfigResolver(tmp_path)
        assert resolver.has_config is True
        assert "@/*" in resolver.paths
        assert "@components/*" in resolver.paths

    def test_no_config_file(self, tmp_path):
        """TsConfigResolver gracefully handles missing config."""
        resolver = TsConfigResolver(tmp_path)
        assert resolver.has_config is False

    def test_loads_jsconfig(self, tmp_path):
        """TsConfigResolver also loads jsconfig.json."""
        jsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@/*": ["src/*"]
                }
            }
        }
        (tmp_path / "jsconfig.json").write_text(json.dumps(jsconfig))
        
        resolver = TsConfigResolver(tmp_path)
        assert resolver.has_config is True


class TestAliasResolution:
    """Test path alias resolution."""

    def test_alias_resolves_to_file(self, tmp_path):
        """@/utils/api resolves to src/utils/api.ts."""
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {"@/*": ["src/*"]}
            }
        }
        (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig))
        
        files = [
            _make_file("src/App.tsx"),
            _make_file("src/utils/api.ts"),
        ]
        resolver = DependencyResolver(files, repo_root=tmp_path)
        imp = _make_import("@/utils/api")
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/utils/api.ts"

    def test_alias_resolves_to_index(self, tmp_path):
        """@/components/Button resolves to src/components/Button/index.tsx."""
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {"@/*": ["src/*"]}
            }
        }
        (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig))
        
        files = [
            _make_file("src/App.tsx"),
            _make_file("src/components/Button/index.tsx"),
        ]
        resolver = DependencyResolver(files, repo_root=tmp_path)
        imp = _make_import("@/components/Button")
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/components/Button/index.tsx"

    def test_alias_unresolvable_generates_diagnostic(self, tmp_path):
        """@/nonexistent should be UNRESOLVED with diagnostic."""
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {"@/*": ["src/*"]}
            }
        }
        (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig))
        
        files = [_make_file("src/App.tsx")]
        resolver = DependencyResolver(files, repo_root=tmp_path)
        imp = _make_import("@/nonexistent")
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.UNRESOLVED
        assert len(resolver.diagnostics) >= 1
        diag = resolver.diagnostics[0]
        assert diag.diagnostic_type == "UNRESOLVED_ALIAS_TARGET"
        assert diag.assigned_category == "UNRESOLVED"

    def test_non_alias_import_not_affected(self, tmp_path):
        """Non-alias imports should bypass alias resolution."""
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {"@/*": ["src/*"]}
            }
        }
        (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig))
        
        files = [_make_file("src/App.tsx")]
        resolver = DependencyResolver(files, repo_root=tmp_path)
        imp = _make_import("react")
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.EXTERNAL
