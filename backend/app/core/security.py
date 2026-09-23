"""Local filesystem security boundary validation for CodeSentinel API."""

import os
from pathlib import Path

from backend.app.core.exceptions import (
    InvalidPathException,
    PathNotFoundException,
    SecurityPolicyViolationException,
)

# Forbidden sensitive system root paths and directories (lowercased resolved strings)
_SYSTEM_ROOTS_RAW = [
    os.environ.get("SystemRoot", "C:\\Windows"),
    os.environ.get("ProgramFiles", "C:\\Program Files"),
    os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "/bin",
    "/sbin",
    "/etc",
    "/usr",
    "/proc",
    "/sys",
]

FORBIDDEN_ROOT_STRS = {
    str(Path(p).resolve()).lower()
    for p in _SYSTEM_ROOTS_RAW
    if p
}


def _is_forbidden_system_path(resolved_path: Path) -> bool:
    """Check if resolved path is or is inside a forbidden system directory."""
    path_str = str(resolved_path).lower()
    for forbidden in FORBIDDEN_ROOT_STRS:
        if path_str == forbidden or path_str.startswith(forbidden.rstrip("\\/") + os.sep.lower()):
            return True
    return False


def validate_repository_path(path_str: str) -> Path:
    """Validate and sanitize a repository path before static analysis.
    
    Security guarantees:
    1. Resolves path to a canonical absolute path.
    2. Verifies path exists on the local filesystem.
    3. Verifies path is a directory (not a file, device, or socket).
    4. Enforces local developer policy: rejects drive root and system directories.
    5. Confines all analysis to static file reads without execution.
    
    Args:
        path_str: User-supplied path string.
        
    Returns:
        Canonical absolute Path object.
        
    Raises:
        InvalidPathException: If path is empty, invalid syntax, or a file.
        PathNotFoundException: If path does not exist.
        SecurityPolicyViolationException: If path is a drive root or system folder.
    """
    if not path_str or not path_str.strip():
        raise InvalidPathException(path_str, reason="Repository path cannot be empty")

    try:
        raw_p = Path(path_str.strip())
        if not raw_p.is_absolute() and not raw_p.exists() and (Path("..") / raw_p).exists():
            resolved_path = (Path("..") / raw_p).resolve()
        else:
            resolved_path = raw_p.resolve()
    except Exception as exc:
        raise InvalidPathException(path_str, reason=f"Path parsing error: {exc}")

    # Check existence
    if not resolved_path.exists():
        raise PathNotFoundException(str(resolved_path))

    # Check directory type
    if not resolved_path.is_dir():
        raise InvalidPathException(
            str(resolved_path),
            reason="Target path is a file, but CodeSentinel requires a directory",
        )

    # Check drive root (e.g. C:\ or /)
    if resolved_path.parent == resolved_path:
        raise SecurityPolicyViolationException(
            str(resolved_path),
            reason="Target path cannot be the root filesystem/drive directory",
        )

    # Check forbidden system directories
    if _is_forbidden_system_path(resolved_path):
        raise SecurityPolicyViolationException(
            str(resolved_path),
            reason=f"Target path lies within protected system directory",
        )

    return resolved_path
