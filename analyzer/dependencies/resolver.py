"""Dependency resolver mapping import statements to repository files or external packages.

Phase 6 enhancements:
- Python: src/ layout support, from-import submodule resolution, strict UNRESOLVED enforcement
- JS/TS: Extension probing, index resolution, parent directory traversal
- Static alias resolution via tsconfig.json / jsconfig.json paths mapping
- Structured dependency diagnostics for resolution failures
"""

import json
import posixpath
from pathlib import Path
from typing import Optional, Set

from analyzer.dependencies.imports import is_node_builtin, is_python_stdlib
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ImportCategory, ImportStatement, ParsedFile
from analyzer.models.results import DependencyDiagnostic


class TsConfigResolver:
    """Parses tsconfig.json / jsconfig.json and resolves path alias mappings.
    
    Supports deterministic resolution of:
    - compilerOptions.baseUrl
    - compilerOptions.paths (e.g., "@/*": ["src/*"])
    
    Ambiguous or unsupported configs fall back safely to UNRESOLVED with diagnostic.
    """

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.base_url: Optional[str] = None
        self.paths: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        """Load tsconfig.json or jsconfig.json from the repository root or common subdirectories."""
        candidates = [
            self.repo_root / "tsconfig.json",
            self.repo_root / "jsconfig.json",
            self.repo_root / "frontend" / "tsconfig.json",
            self.repo_root / "frontend" / "jsconfig.json",
        ]
        for config_path in candidates:
            if config_path.is_file():
                try:
                    raw = config_path.read_text(encoding="utf-8", errors="replace")
                    data = json.loads(raw)
                    compiler_options = data.get("compilerOptions", {})
                    self.base_url = compiler_options.get("baseUrl")
                    self.paths = compiler_options.get("paths", {})
                    # Store the config file's parent for relative baseUrl resolution
                    self._config_dir = config_path.parent
                    return
                except (json.JSONDecodeError, OSError):
                    pass
        self._config_dir = self.repo_root

    @property
    def has_config(self) -> bool:
        """Return True if a tsconfig/jsconfig was successfully loaded."""
        return bool(self.base_url) or bool(self.paths)

    def resolve_alias(self, import_specifier: str, file_set: Set[str], find_js_ts_file) -> tuple[Optional[str], Optional[DependencyDiagnostic]]:
        """Attempt to resolve an import specifier via path alias mappings.
        
        Args:
            import_specifier: Raw import string (e.g., '@/utils/api').
            file_set: Set of repository-relative file paths (forward-slash normalized).
            find_js_ts_file: Callable to probe file candidates.
        
        Returns:
            Tuple of (resolved_path or None, diagnostic or None).
        """
        if not self.paths:
            return None, None

        config_dir_rel = self._config_dir.relative_to(self.repo_root).as_posix()
        if config_dir_rel == ".":
            config_dir_rel = ""

        for pattern, targets in self.paths.items():
            # Match wildcard patterns like "@/*" or exact patterns like "@utils"
            if pattern.endswith("/*"):
                prefix = pattern[:-2]
                if import_specifier.startswith(prefix + "/") or import_specifier == prefix:
                    suffix = import_specifier[len(prefix) + 1:] if import_specifier.startswith(prefix + "/") else ""
                    for target_pattern in targets:
                        if target_pattern.endswith("/*"):
                            target_prefix = target_pattern[:-2]
                        else:
                            target_prefix = target_pattern
                        
                        # Build candidate path relative to baseUrl or config dir
                        base = self.base_url or "."
                        candidate_base = posixpath.normpath(
                            posixpath.join(config_dir_rel, base, target_prefix, suffix)
                        )
                        
                        resolved = find_js_ts_file(candidate_base)
                        if resolved:
                            return resolved, None

                    # Alias matched but no file found
                    return None, DependencyDiagnostic(
                        file_path="",  # Will be filled by caller
                        source_module=import_specifier,
                        diagnostic_type="UNRESOLVED_ALIAS_TARGET",
                        message=f"Path alias '{pattern}' matched import '{import_specifier}' but target file was not found in the repository.",
                        reason=f"Alias pattern '{pattern}' maps to {targets} but no candidate file exists on disk.",
                        assigned_category="UNRESOLVED",
                    )
            else:
                # Exact pattern match
                if import_specifier == pattern:
                    for target_pattern in targets:
                        base = self.base_url or "."
                        candidate_base = posixpath.normpath(
                            posixpath.join(config_dir_rel, base, target_pattern)
                        )
                        resolved = find_js_ts_file(candidate_base)
                        if resolved:
                            return resolved, None

                    return None, DependencyDiagnostic(
                        file_path="",
                        source_module=import_specifier,
                        diagnostic_type="UNRESOLVED_ALIAS_TARGET",
                        message=f"Exact path alias '{pattern}' matched import '{import_specifier}' but target file was not found.",
                        reason=f"Alias pattern '{pattern}' maps to {targets} but no candidate exists.",
                        assigned_category="UNRESOLVED",
                    )

        return None, None


class DependencyResolver:
    """Resolves raw import module strings to repository files or categorized external dependencies.
    
    Phase 6 improvements:
    - Python: src/ layout auto-detection, from-import submodule file resolution,
      accurate multi-level relative import traversal, strict UNRESOLVED for failed local patterns.
    - JS/TS: Extended extension probing, directory index resolution, parent traversal.
    - Static path alias resolution via tsconfig.json / jsconfig.json.
    - Structured dependency diagnostics for resolution failures.
    Unresolved imports remain explicitly marked as UNRESOLVED and are never silently discarded.
    """

    def __init__(
        self,
        discovered_files: list[DiscoveredFileMetadata],
        repo_root: Optional[Path] = None,
    ):
        self.discovered_files = discovered_files
        self.file_set: Set[str] = {f.relative_path.replace("\\", "/") for f in discovered_files}
        self.py_module_map = self._build_python_module_map()
        self.source_roots = self._detect_source_roots()
        self.diagnostics: list[DependencyDiagnostic] = []
        # Initialize TsConfig resolver if repo_root provided
        self.tsconfig_resolver: Optional[TsConfigResolver] = None
        if repo_root:
            self.tsconfig_resolver = TsConfigResolver(repo_root)
            if not self.tsconfig_resolver.has_config:
                self.tsconfig_resolver = None

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
            self._resolve_python_import(importer_norm, importer_dir, imp)
        elif language in ("JAVASCRIPT", "TYPESCRIPT"):
            self._resolve_js_ts_import(importer_norm, importer_dir, imp)
        else:
            imp.dependency_category = ImportCategory.UNRESOLVED

    def _resolve_python_import(self, importer_path: str, importer_dir: str, imp: ImportStatement) -> None:
        raw = imp.source_module.strip()

        # 1. Handle relative Python imports (e.g. .user, ..services, from . import x)
        if imp.is_relative or raw.startswith("."):
            dots = len(raw) - len(raw.lstrip("."))
            sub_mod = raw.lstrip(".")
            # Walk up (dots - 1) directories from importer_dir
            base_dir = importer_dir
            for _ in range(dots - 1):
                parent = posixpath.dirname(base_dir)
                if parent == base_dir:
                    # Cannot traverse above repository root
                    break
                base_dir = parent

            resolved = self._find_python_file(base_dir, sub_mod) if sub_mod else None
            # Also try: from .foo import bar -> check foo/bar.py
            if not resolved and sub_mod and imp.imported_names:
                for name in imp.imported_names:
                    resolved = self._find_python_file(base_dir, f"{sub_mod}.{name}")
                    if resolved:
                        break

            # Try bare package init for `from . import x`
            if not resolved and not sub_mod:
                init_path = f"{base_dir}/__init__.py" if base_dir else "__init__.py"
                if init_path in self.file_set:
                    resolved = init_path

            if resolved:
                imp.resolved_path = resolved
                imp.dependency_category = ImportCategory.LOCAL
            else:
                imp.dependency_category = ImportCategory.UNRESOLVED
                self._add_diagnostic(
                    importer_path, raw, imp.line_number,
                    "UNRESOLVED_RELATIVE_IMPORT",
                    f"Relative import '{raw}' could not be resolved to any repository file.",
                    f"Searched from directory '{importer_dir}' with {dots} dot level(s) and submodule '{sub_mod}'.",
                )
            return

        # 2. Check standard library
        if is_python_stdlib(raw):
            imp.dependency_category = ImportCategory.STDLIB
            return

        # 3. Check if import resolves to local repository files
        # Try from root first
        resolved = self._find_python_file("", raw)

        # Try from-import submodule: from foo import bar -> foo/bar.py or foo/bar/__init__.py
        if not resolved and imp.imported_names:
            for name in imp.imported_names:
                resolved = self._find_python_file("", f"{raw}.{name}")
                if resolved:
                    break

        if not resolved:
            # Try from importer directory
            resolved = self._find_python_file(importer_dir, raw)

        if not resolved:
            # Try looking up in precomputed module map
            resolved = self.py_module_map.get(raw)

        # Phase 6: Try source roots (e.g. src/ layout)
        if not resolved:
            for src_root in self.source_roots:
                resolved = self._find_python_file(src_root, raw)
                if resolved:
                    break
                # Also try from-import submodule under source root
                if imp.imported_names:
                    for name in imp.imported_names:
                        resolved = self._find_python_file(src_root, f"{raw}.{name}")
                        if resolved:
                            break
                    if resolved:
                        break

        if resolved:
            imp.resolved_path = resolved
            imp.dependency_category = ImportCategory.LOCAL
        else:
            # Check if the import looks like it targets a known internal package root
            # If it matches a known local package prefix, classify as UNRESOLVED, not EXTERNAL
            if self._is_likely_local_import(raw):
                imp.dependency_category = ImportCategory.UNRESOLVED
                self._add_diagnostic(
                    importer_path, raw, imp.line_number,
                    "UNRESOLVED_LOCAL_IMPORT",
                    f"Import '{raw}' appears to target a local package but could not be resolved.",
                    f"Module prefix matches a known local package root but no file was found.",
                )
            else:
                # Assumed external package (e.g. external_lib)
                imp.dependency_category = ImportCategory.EXTERNAL

    def _resolve_js_ts_import(self, importer_path: str, importer_dir: str, imp: ImportStatement) -> None:
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
                self._add_diagnostic(
                    importer_path, raw, imp.line_number,
                    "UNRESOLVED_RELATIVE_IMPORT",
                    f"Relative import '{raw}' could not be resolved to any repository file.",
                    f"Searched from directory '{importer_dir}' with extension probing and index file resolution.",
                )
            return

        # 3. Try alias resolution via tsconfig.json / jsconfig.json
        if self.tsconfig_resolver:
            resolved, diag = self.tsconfig_resolver.resolve_alias(
                raw, self.file_set, self._find_js_ts_file,
            )
            if resolved:
                imp.resolved_path = resolved
                imp.dependency_category = ImportCategory.LOCAL
                return
            if diag:
                diag.file_path = importer_path
                diag.line_number = imp.line_number
                self.diagnostics.append(diag)
                imp.dependency_category = ImportCategory.UNRESOLVED
                return

        # 4. Non-relative imports (e.g. 'react', '@xyflow/react', 'lodash')
        # Check if it matches a top-level repository file or path alias
        resolved = self._find_js_ts_file(raw)
        if resolved:
            imp.resolved_path = resolved
            imp.dependency_category = ImportCategory.LOCAL
        else:
            imp.dependency_category = ImportCategory.EXTERNAL

    def _find_python_file(self, base_dir: str, module_path: str) -> Optional[str]:
        """Convert dot-separated module path to candidate relative file paths."""
        if not module_path:
            return None
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
        index_names = ["index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs", "index.cjs"]
        for idx_name in index_names:
            idx = f"{base_candidate}/{idx_name}"
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

    def _detect_source_roots(self) -> list[str]:
        """Detect common Python source root directories (e.g. src/, lib/)."""
        source_root_candidates = ["src", "lib"]
        detected = []
        for candidate in source_root_candidates:
            # Check if any discovered file has this as a path prefix
            for f in self.discovered_files:
                rel = f.relative_path.replace("\\", "/")
                if rel.startswith(f"{candidate}/") and f.extension == ".py":
                    detected.append(candidate)
                    break
        return detected

    def _is_likely_local_import(self, module_name: str) -> bool:
        """Check if a module name looks like it targets a known local package."""
        root_prefix = module_name.split(".")[0]
        # Check if any discovered file's path starts with this prefix
        for f in self.discovered_files:
            rel = f.relative_path.replace("\\", "/")
            parts = rel.split("/")
            if parts and parts[0] == root_prefix:
                return True
        # Also check source roots
        for src_root in self.source_roots:
            for f in self.discovered_files:
                rel = f.relative_path.replace("\\", "/")
                if rel.startswith(f"{src_root}/"):
                    subpath = rel[len(src_root) + 1:]
                    parts = subpath.split("/")
                    if parts and parts[0] == root_prefix:
                        return True
        return False

    def _add_diagnostic(
        self,
        file_path: str,
        source_module: str,
        line_number: Optional[int],
        diagnostic_type: str,
        message: str,
        reason: str,
    ) -> None:
        """Record a dependency resolution diagnostic."""
        self.diagnostics.append(
            DependencyDiagnostic(
                file_path=file_path,
                source_module=source_module,
                line_number=line_number,
                diagnostic_type=diagnostic_type,
                message=message,
                reason=reason,
                assigned_category="UNRESOLVED",
            )
        )
