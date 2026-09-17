"""Ignore and exclusion rule matcher supporting .gitignore and .sentinelignore."""

import fnmatch
from pathlib import Path
from pydantic import BaseModel, Field


class IngestionConfig(BaseModel):
    """Configuration options for repository ingestion and safety limits."""
    max_file_size_bytes: int = Field(
        default=5 * 1024 * 1024,  # 5 MB
        ge=1024,
        description="Maximum individual file size in bytes to read and parse"
    )
    max_files: int = Field(
        default=50_000,
        ge=1,
        description="Maximum number of discovered files before raising an error"
    )
    encoding: str = Field(default="utf-8")


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "coverage",
    ".next",
    ".cache",
    ".turbo",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
}

DEFAULT_EXCLUDED_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dll",
    "*.dylib",
    "*.exe",
    "*.bin",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


class IgnoreEngine:
    """Matches files and directories against default exclusions, .gitignore, and .sentinelignore."""

    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.custom_patterns: list[str] = []
        self._load_ignore_files()

    def _load_ignore_files(self) -> None:
        """Parse .gitignore and .sentinelignore files located in the repository root."""
        for filename in [".gitignore", ".sentinelignore"]:
            ignore_file = self.root_path / filename
            if ignore_file.is_file():
                try:
                    content = ignore_file.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Normalize path separators
                            clean_pat = line.replace("\\", "/")
                            self.custom_patterns.append(clean_pat)
                except Exception:
                    # Non-fatal if ignore file cannot be read
                    pass

    def should_ignore(self, relative_path: str, is_dir: bool = False) -> bool:
        """Evaluate whether a path should be excluded from analysis.
        
        Args:
            relative_path: Forward-slash normalized relative path from repository root.
            is_dir: True if evaluating a directory.
            
        Returns:
            True if the path should be ignored.
        """
        # Normalize relative path to forward slashes
        norm_path = relative_path.replace("\\", "/").strip("/")
        parts = norm_path.split("/")

        # 1. Check default directory names
        for part in parts:
            if part in DEFAULT_EXCLUDED_DIRS:
                return True

        filename = parts[-1] if parts else ""

        # 2. Check default file patterns
        if not is_dir:
            for pat in DEFAULT_EXCLUDED_PATTERNS:
                if fnmatch.fnmatch(filename, pat):
                    return True

        # 3. Check custom patterns from .gitignore and .sentinelignore
        for pattern in self.custom_patterns:
            pat_is_dir_only = pattern.endswith("/")
            clean_pat = pattern.rstrip("/")

            if pat_is_dir_only:
                # Matches directory itself or any file/folder within that directory
                if norm_path == clean_pat or norm_path.startswith(f"{clean_pat}/"):
                    return True
                parent_parts = parts if is_dir else parts[:-1]
                if any(fnmatch.fnmatch(part, clean_pat) for part in parent_parts):
                    return True
                continue

            # Direct match or glob match against basename or full relative path
            if "/" in clean_pat:
                if fnmatch.fnmatch(norm_path, clean_pat) or fnmatch.fnmatch(norm_path, f"{clean_pat}/*"):
                    return True
            else:
                if fnmatch.fnmatch(filename, clean_pat):
                    return True
                # Also match any directory in parts if pattern has no slash
                if any(fnmatch.fnmatch(part, clean_pat) for part in parts):
                    return True

        return False
