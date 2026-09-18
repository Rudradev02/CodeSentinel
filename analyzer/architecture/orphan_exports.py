"""Intra-repository orphan export analyzer.

Reconciles declared module exports against internal import statements to detect
public symbols that have zero observable internal callers within the repository.
Conservatively accounts for whole-module imports, namespace imports, re-exports,
and designated entry-point files.
"""

from pathlib import Path
from typing import Optional, Set
from pydantic import BaseModel, Field

from analyzer.models.parse import ImportCategory, ParsedFile


DEFAULT_ENTRY_POINTS: set[str] = {
    "__main__.py",
    "main.py",
    "manage.py",
    "app.py",
    "wsgi.py",
    "asgi.py",
    "conftest.py",
    "index.ts",
    "index.js",
    "index.tsx",
    "index.jsx",
    "main.ts",
    "main.tsx",
    "app.tsx",
    "app.jsx",
    "vite.config.ts",
    "next.config.js",
    "tailwind.config.js",
    "postcss.config.js",
}


class OrphanExportRecord(BaseModel):
    """Structured record of an unreferenced exported symbol."""
    file_path: str = Field(..., description="Repository-relative file path containing the export")
    symbol_name: str = Field(..., description="Name of the unused exported symbol")
    line_number: Optional[int] = Field(default=None, description="Declaration line number")
    is_default: bool = Field(default=False)


class OrphanExportAnalyzer:
    """Detects potentially orphaned exported symbols across repository source files."""

    def __init__(self, custom_entry_points: Optional[set[str]] = None):
        self.entry_points = (custom_entry_points or set()) | DEFAULT_ENTRY_POINTS

    def is_entry_point_file(self, relative_path: str) -> bool:
        """Check if a file should be exempted as an architectural entry point."""
        clean_path = relative_path.replace("\\", "/").strip("/")
        p = Path(clean_path)
        filename = p.name.lower()

        # 1. Exact filename match
        if filename in self.entry_points:
            return True

        # 2. Python package root or index file
        if filename == "__init__.py" or filename.startswith("index."):
            return True

        # 3. Test files or test directory contents
        parts = [part.lower() for part in p.parts]
        if "tests" in parts or "test" in parts:
            return True
        if filename.startswith("test_") or filename.endswith("_test.py"):
            return True
        if filename.endswith(".test.ts") or filename.endswith(".test.js") or filename.endswith(".spec.ts"):
            return True

        return False

    def find_orphan_exports(self, parsed_files: list[ParsedFile]) -> list[OrphanExportRecord]:
        """Identify public exports that have no observable internal callers.
        
        Args:
            parsed_files: All normalized ParsedFile objects from the parser phase.
            
        Returns:
            Deterministically sorted list of OrphanExportRecord instances.
        """
        # 1. Collect all whole-module imported file paths
        # If a file is imported as a whole module (e.g. import foo, import * as f), all its exports are considered referenced.
        whole_module_imported_files: Set[str] = set()

        # 2. Specific symbol references: map resolved_path -> set of imported symbol names
        symbol_references: dict[str, Set[str]] = {}

        for pf in parsed_files:
            for imp in pf.imports:
                if imp.dependency_category != ImportCategory.LOCAL or not imp.resolved_path:
                    continue

                res_path = imp.resolved_path.replace("\\", "/")

                # Detect whole-module or wildcard imports
                # In Python: empty imported_names, "*", or importing module itself (import pkg.helpers)
                # In JS/TS: empty imported_names or "*" (import * as foo from ...)
                is_whole_module = (
                    not imp.imported_names
                    or "*" in imp.imported_names
                    or any(
                        name == imp.source_module or name == imp.source_module.split(".")[-1]
                        for name in imp.imported_names
                    )
                )
                if is_whole_module:
                    whole_module_imported_files.add(res_path)
                else:
                    symbol_references.setdefault(res_path, set()).update(imp.imported_names)

        # 3. Check each parsed file's exports
        orphan_records: list[OrphanExportRecord] = []

        for pf in parsed_files:
            file_rel = pf.relative_path.replace("\\", "/")

            # Skip entry-point files, package inits, and index files
            if self.is_entry_point_file(file_rel):
                continue

            # If the entire file is imported anywhere as a whole module, skip all its exports
            if file_rel in whole_module_imported_files:
                continue

            referenced_names = symbol_references.get(file_rel, set())

            for exp in pf.exports:
                # Ignore internal private symbols
                if exp.name.startswith("_") and not exp.name.startswith("__"):
                    continue

                # If the exported symbol name is referenced by at least one local import
                if exp.name in referenced_names:
                    continue

                # If default export is referenced (often imported under arbitrary alias)
                if exp.is_default and ("default" in referenced_names or file_rel in symbol_references):
                    continue

                orphan_records.append(
                    OrphanExportRecord(
                        file_path=file_rel,
                        symbol_name=exp.name,
                        line_number=exp.line_number,
                        is_default=exp.is_default,
                    )
                )

        # 4. Strictly sort orphan records deterministically
        orphan_records.sort(
            key=lambda r: (r.file_path, r.line_number or 0, r.symbol_name)
        )
        return orphan_records
