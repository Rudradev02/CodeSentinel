"""Recursive file discovery and source cataloging engine."""

import os
from pathlib import Path
from typing import Optional

from analyzer.ingestion.ignore import IgnoreEngine, IngestionConfig
from analyzer.models.metadata import DiscoveredFileMetadata

# Supported source file extensions mapped to internal language IDs
SUPPORTED_EXTENSIONS = {
    ".py": "PYTHON",
    ".js": "JAVASCRIPT",
    ".jsx": "JAVASCRIPT",
    ".mjs": "JAVASCRIPT",
    ".cjs": "JAVASCRIPT",
    ".ts": "TYPESCRIPT",
    ".tsx": "TYPESCRIPT",
}

# Manifest and configuration filenames useful for framework & dependency discovery
MANIFEST_FILES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "manage.py",
}


def is_binary_file(file_path: Path) -> bool:
    """Check if file appears to be binary by testing for null bytes in initial chunk."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def count_lines(file_path: Path) -> int:
    """Safely count lines in a text file."""
    try:
        with open(file_path, "rb") as f:
            lines = 0
            for chunk in iter(lambda: f.read(1024 * 64), b""):
                lines += chunk.count(b"\n")
            return lines + 1
    except Exception:
        return 0


def discover_repository_files(
    repo_path: Path,
    config: Optional[IngestionConfig] = None,
    ignore_engine: Optional[IgnoreEngine] = None,
) -> tuple[list[DiscoveredFileMetadata], list[Path]]:
    """Recursively scan repository and catalog supported source files.
    
    Args:
        repo_path: Absolute validated repository root path.
        config: IngestionConfig with size and file count limits.
        ignore_engine: Initialized IgnoreEngine instance.
        
    Returns:
        Tuple of (list of DiscoveredFileMetadata, list of manifest file Paths).
        
    Raises:
        RuntimeError: If maximum file count limit is exceeded.
    """
    cfg = config or IngestionConfig()
    ignorer = ignore_engine or IgnoreEngine(repo_path)

    discovered_files: list[DiscoveredFileMetadata] = []
    manifest_paths: list[Path] = []
    total_scanned = 0

    for root, dirs, files in os.walk(repo_path, topdown=True):
        root_path = Path(root)
        rel_root = root_path.relative_to(repo_path).as_posix()
        if rel_root == ".":
            rel_root = ""

        # Filter directories in-place to prevent os.walk from descending into ignored trees
        dirs_to_keep = []
        for d in dirs:
            dir_rel = f"{rel_root}/{d}" if rel_root else d
            if not ignorer.should_ignore(dir_rel, is_dir=True):
                dirs_to_keep.append(d)
        dirs[:] = dirs_to_keep

        # Scan files in current directory
        for f in files:
            total_scanned += 1
            if total_scanned > cfg.max_files:
                raise RuntimeError(
                    f"Repository exceeds maximum file count safety limit ({cfg.max_files} files)"
                )

            file_rel = f"{rel_root}/{f}" if rel_root else f
            if ignorer.should_ignore(file_rel, is_dir=False):
                continue

            file_path = root_path / f
            file_ext = file_path.suffix.lower()
            file_lower_name = f.lower()

            # Record manifest paths if present
            if file_lower_name in MANIFEST_FILES or f == "manage.py":
                manifest_paths.append(file_path)

            # Check if this is a supported source file
            if file_ext not in SUPPORTED_EXTENSIONS:
                continue

            try:
                stat = file_path.stat()
                size_bytes = stat.st_size

                # Skip oversized files exceeding configured limit
                if size_bytes > cfg.max_file_size_bytes:
                    continue

                # Skip binary files
                if is_binary_file(file_path):
                    continue

                loc = count_lines(file_path)

                discovered_files.append(
                    DiscoveredFileMetadata(
                        path=str(file_path.resolve()),
                        relative_path=file_rel,
                        extension=file_ext,
                        language=SUPPORTED_EXTENSIONS[file_ext],
                        size_bytes=size_bytes,
                        line_count=loc,
                    )
                )
            except (OSError, PermissionError):
                # Gracefully skip files with permission/read errors
                continue

    # Sort files deterministically by relative path
    discovered_files.sort(key=lambda item: item.relative_path)
    return discovered_files, manifest_paths
