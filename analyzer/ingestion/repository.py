"""Safe repository ingestion and filesystem path validation."""

import os
from pathlib import Path


def validate_repository_path(path: Path | str) -> Path:
    """Validate and resolve target repository directory safely.
    
    Ensures:
    - Path is not empty
    - Target exists on the filesystem
    - Target is a directory (not a regular file or socket)
    - Target directory has read permissions
    
    Args:
        path: Path string or Path object.
        
    Returns:
        Resolved absolute Path.
        
    Raises:
        ValueError: If path is empty, invalid, or not a directory.
        FileNotFoundError: If the path does not exist.
        PermissionError: If directory cannot be read.
    """
    if not path:
        raise ValueError("Repository path cannot be empty")

    repo_path = Path(path).resolve()

    if not repo_path.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo_path}")

    if not repo_path.is_dir():
        raise ValueError(f"Repository path must be a directory, not a file: {repo_path}")

    # Check read permissions safely
    if not os.access(repo_path, os.R_OK):
        raise PermissionError(f"Permission denied reading repository directory: {repo_path}")

    return repo_path
