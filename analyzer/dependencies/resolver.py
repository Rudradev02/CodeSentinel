"""Dependency resolver mapping import statements to repository files or external packages."""

import posixpath
from pathlib import Path
from typing import Optional, Set

from analyzer.dependencies.imports import is_node_builtin, is_python_stdlib
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile


class DependencyResolver:
    """Resolves raw import module strings to repository files or categorized external dependencies.
    
    Phase 2 focuses on common local resolution patterns. JavaScript/TypeScript resolution
    is intentionally limited to standard relative conventions (./, ../, extensions, and index files).
    Unresolved imports remain explicitly marked as UNRESOLVED and are never silently discarded.
    """

    def __init__(self, discovered_files: list[DiscoveredFileMetadata]):
        self.discovered_files = discovered_files
        self.file_set: Set[str] = {f.relative_path.replace("\\", "/") for f in discovered_files}
        self.py_module_map = self._build_python_module_map()

    def resolve_all(self, parsed_files: list[ParsedFile]) -> None:
        """Resolve all imports in-place across the provided parsed files."""
        for pf in parsed_files:
            for imp in pf.imports:
                self.resolve_import(pf.relative_path, pf.language, imp)

    def resolve_import(self, importer_rel_path: str, language: str, imp: ImportStatement) -> None:
        """Resolve an individual import statement and assign category and resolved_path."""
        importer_norm = importer_rel_path.replace("\\", "/")
        importer_dir = posixpath.dirname(importer_norm)

        if language == "PYTHON":
            self._resolve_python_import(importer_dir, imp)
        elif language in ("JAVASCRIPT", "TYPESCRIPT"):
            self._resolve_js_ts_import(importer_dir, imp)
        else:
            imp.dependency_category = ImportCategory.UNRESOLVED

    def _resolve_python_import(self, importer_dir: str, imp: ImportStatement) -> None:
        raw = imp.source_module.strip()

        # 1. Handle relative Python imports (e.g. .user, ..services)
        if imp.is_relative or raw.startswith("."):
            dots = len(raw) - len(raw.lstrip("."))
            sub_mod = raw.lstrip(".")
            # Walk up (dots - 1) directories from importer_dir
            base_dir = importer_dir
            for _ in range(dots - 1):
                base_dir = posixpath.dirname(base_dir)

            resolved = self._find_python_file(base_dir, sub_mod)
            if resolved:
                imp.resolved_path = resolved
                imp.dependency_category = ImportCategory.LOCAL
            else:
                imp.dependency_category = ImportCategory.UNRESOLVED
            return

        # 2. Check standard library
        if is_python_stdlib(raw):
            imp.dependency_category = ImportCategory.STDLIB
            return

        # 3. Check if import resolves to local repository files (e.g. app.services or services.user_service)
        # Try from root first
        resolved = self._find_python_file("", raw)
        if not resolved:
            # Try from importer directory
            resolved = self._find_python_file(importer_dir, raw)
        if not resolved:
            # Try looking up in precomputed module map
            resolved = self.py_module_map.get(raw)

        if resolved:
            imp.resolved_path = resolved
            imp.dependency_category = ImportCategory.LOCAL
        else:
            # Assumed external package (e.g. external_lib)
            imp.dependency_category = ImportCategory.EXTERNAL

    def _resolve_js_ts_import(self, importer_dir: str, imp: ImportStatement) -> None:
        raw = imp.source_module.strip()

        # 1. Check Node.js built-ins
        if is_node_builtin(raw):
            imp.dependency_category = ImportCategory.STDLIB
            return

        # 2. Handle relative imports (e.g. ./components/Button, ../utils/api)
        if imp.is_relative or raw.startswith("."):
            target_norm = posixpath.normpath(posixpath.join(importer_dir, raw))
            resolved = self._find_js_ts_file(target_norm)

            if resolved:
                imp.resolved_path = resolved
                imp.dependency_category = ImportCategory.LOCAL
            else:
                imp.dependency_category = ImportCategory.UNRESOLVED
            return

        # 3. Non-relative imports (e.g. 'react', '@xyflow/react', 'lodash')
        # Check if it matches a top-level repository file or path alias
        resolved = self._find_js_ts_file(raw)
        if resolved:
            imp.resolved_path = resolved
            imp.dependency_category = ImportCategory.LOCAL
        else:
            imp.dependency_category = ImportCategory.EXTERNAL

    def _find_python_file(self, base_dir: str, module_path: str) -> Optional[str]:
        """Convert dot-separated module path to candidate relative file paths."""
        rel_candidate = module_path.replace(".", "/")
        full_candidate = posixpath.normpath(posixpath.join(base_dir, rel_candidate)) if base_dir else rel_candidate

        # 1. Direct module: full_candidate.py
        as_py = f"{full_candidate}.py"
        if as_py in self.file_set:
            return as_py

        # 2. Package module: full_candidate/__init__.py
        as_pkg = f"{full_candidate}/__init__.py"
        if as_pkg in self.file_set:
            return as_pkg

        return None

    def _find_js_ts_file(self, base_candidate: str) -> Optional[str]:
        """Search for matching JS/TS file across supported extensions and index files."""
        # Exact match (if extension was included in import statement)
        if base_candidate in self.file_set:
            return base_candidate

        # Supported extension candidates in priority order
        extensions = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
        for ext in extensions:
            cand = f"{base_candidate}{ext}"
            if cand in self.file_set:
                return cand

        # Directory index candidates
        index_candidates = [
            f"{base_candidate}/index.ts",
            f"{base_candidate}/index.tsx",
            f"{base_candidate}/index.js",
            f"{base_candidate}/index.jsx",
        ]
        for idx in index_candidates:
            if idx in self.file_set:
                return idx

        return None

    def _build_python_module_map(self) -> dict[str, str]:
        """Map common dot-notated module paths to their relative repository file paths."""
        mod_map = {}
        for f in self.discovered_files:
            if f.extension == ".py":
                rel = f.relative_path.replace("\\", "/")
                # Strip .py
                base = rel[:-3]
                if base.endswith("/__init__"):
                    base = base[:-9]
                dot_mod = base.replace("/", ".")
                mod_map[dot_mod] = rel

                # Also support omitting top-level folder (e.g. app.services.x -> services.x)
                parts = dot_mod.split(".")
                if len(parts) > 1:
                    sub_mod = ".".join(parts[1:])
                    if sub_mod not in mod_map:
                        mod_map[sub_mod] = rel
        return mod_map
