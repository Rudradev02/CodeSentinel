"""Phase 6: JavaScript/TypeScript dependency resolution tests.

Tests cover:
- Relative path imports with and without extensions (.ts, .tsx, .js, .jsx)
- Index resolution (/components/Button/index.tsx)
- Parent directory imports (../../shared/utils)
- Re-exports (export * from './module', export { a } from './a')
- CommonJS require("./local")
- Node built-ins with node: prefix (node:fs, node:path)
"""

import pytest
from pathlib import Path
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile
from analyzer.models.graph import ImportType
from analyzer.parsing.javascript_parser import JavaScriptParser
from analyzer.parsing.typescript_parser import TypeScriptParser


def _make_file(rel_path: str, lang: str = None) -> DiscoveredFileMetadata:
    """Create a minimal DiscoveredFileMetadata for testing."""
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


class TestJsRelativeImports:
    """Test relative JS/TS import resolution."""

    def test_relative_import_with_extension(self):
        """import './utils.js' resolves directly."""
        files = [_make_file("src/app.js"), _make_file("src/utils.js")]
        resolver = DependencyResolver(files)
        imp = _make_import("./utils.js", is_relative=True)
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/utils.js"

    def test_relative_import_without_extension_ts(self):
        """import './utils' resolves to ./utils.ts when it exists."""
        files = [_make_file("src/app.ts"), _make_file("src/utils.ts")]
        resolver = DependencyResolver(files)
        imp = _make_import("./utils", is_relative=True)
        resolver.resolve_import("src/app.ts", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/utils.ts"

    def test_relative_import_without_extension_tsx(self):
        """import './Button' resolves to ./Button.tsx."""
        files = [_make_file("src/App.tsx"), _make_file("src/Button.tsx")]
        resolver = DependencyResolver(files)
        imp = _make_import("./Button", is_relative=True)
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/Button.tsx"


class TestJsIndexResolution:
    """Test directory index file resolution."""

    def test_import_directory_resolves_to_index(self):
        """import './components/Button' resolves to ./components/Button/index.tsx."""
        files = [
            _make_file("src/App.tsx"),
            _make_file("src/components/Button/index.tsx"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("./components/Button", is_relative=True)
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/components/Button/index.tsx"

    def test_import_directory_resolves_to_index_js(self):
        """import './utils' resolves to ./utils/index.js."""
        files = [
            _make_file("src/app.js"),
            _make_file("src/utils/index.js"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("./utils", is_relative=True)
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/utils/index.js"


class TestJsParentTraversal:
    """Test parent directory traversal in imports."""

    def test_parent_directory_import(self):
        """import '../../shared/utils' resolves correctly."""
        files = [
            _make_file("src/features/auth/login.ts"),
            _make_file("src/shared/utils.ts"),
        ]
        resolver = DependencyResolver(files)
        imp = _make_import("../../shared/utils", is_relative=True)
        resolver.resolve_import("src/features/auth/login.ts", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/shared/utils.ts"


class TestJsReExports:
    """Test re-export module specifier extraction by parsers."""

    def test_js_parser_extracts_reexport(self):
        """export { x } from './x' should produce an ImportStatement."""
        parser = JavaScriptParser()
        content = "export { foo } from './foo';\n"
        result = parser.parse(Path("/test.js"), "test.js", content)
        
        # Should have extracted the re-export as an import
        reexport_imports = [i for i in result.imports if i.source_module == "./foo"]
        assert len(reexport_imports) >= 1
        assert reexport_imports[0].is_relative is True

    def test_js_parser_extracts_star_reexport(self):
        """export * from './module' should produce an ImportStatement."""
        parser = JavaScriptParser()
        content = "export * from './module';\n"
        result = parser.parse(Path("/test.js"), "test.js", content)
        
        reexport_imports = [i for i in result.imports if i.source_module == "./module"]
        assert len(reexport_imports) >= 1

    def test_ts_parser_extracts_reexport(self):
        """TypeScript re-export should also be captured."""
        parser = TypeScriptParser()
        content = "export { bar } from './bar';\n"
        result = parser.parse(Path("/test.ts"), "test.ts", content)
        
        reexport_imports = [i for i in result.imports if i.source_module == "./bar"]
        assert len(reexport_imports) >= 1


class TestJsCommonJsRequire:
    """Test CommonJS require() resolution."""

    def test_require_relative(self):
        """const x = require('./utils') resolves to ./utils.js."""
        files = [_make_file("src/app.js"), _make_file("src/utils.js")]
        resolver = DependencyResolver(files)
        imp = _make_import("./utils", is_relative=True)
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.LOCAL
        assert imp.resolved_path == "src/utils.js"


class TestNodeBuiltins:
    """Test Node.js built-in detection."""

    def test_node_prefix_builtin(self):
        """node:fs should be classified as STDLIB."""
        files = [_make_file("src/app.js")]
        resolver = DependencyResolver(files)
        imp = _make_import("node:fs")
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        assert imp.dependency_category == ImportCategory.STDLIB

    def test_node_prefix_path(self):
        """node:path should be classified as STDLIB."""
        files = [_make_file("src/app.js")]
        resolver = DependencyResolver(files)
        imp = _make_import("node:path")
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        assert imp.dependency_category == ImportCategory.STDLIB

    def test_bare_builtin_fs(self):
        """fs (without node: prefix) should be STDLIB."""
        files = [_make_file("src/app.js")]
        resolver = DependencyResolver(files)
        imp = _make_import("fs")
        resolver.resolve_import("src/app.js", "JAVASCRIPT", imp)
        assert imp.dependency_category == ImportCategory.STDLIB

    def test_external_package(self):
        """react should be classified as EXTERNAL."""
        files = [_make_file("src/App.tsx")]
        resolver = DependencyResolver(files)
        imp = _make_import("react")
        resolver.resolve_import("src/App.tsx", "TYPESCRIPT", imp)
        assert imp.dependency_category == ImportCategory.EXTERNAL


class TestJsUnresolved:
    """Test unresolved JS/TS imports."""

    def test_relative_import_unresolved(self):
        """Unresolved relative import stays UNRESOLVED."""
        files = [_make_file("src/app.ts")]
        resolver = DependencyResolver(files)
        imp = _make_import("./nonexistent", is_relative=True)
        resolver.resolve_import("src/app.ts", "TYPESCRIPT", imp)
        
        assert imp.dependency_category == ImportCategory.UNRESOLVED
        assert imp.dependency_category != ImportCategory.EXTERNAL
