"""Safe, read-only local Git repository metadata extraction.

Extracts commit hash, branch name, and clean/dirty working tree status
strictly from local files without remote network queries or hook execution.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
from typing import Optional


@dataclass
class GitMetadata:
    """Provenance metadata extracted from a local Git repository."""

    is_git_repo: bool
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    is_dirty: Optional[bool] = None


def _read_git_dir_directly(git_dir: Path) -> tuple[Optional[str], Optional[str]]:
    """Directly parse .git/HEAD and ref files without spawning subprocesses."""
    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        return None, None

    try:
        head_content = head_file.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return None, None

    branch: Optional[str] = None
    commit_hash: Optional[str] = None

    if head_content.startswith("ref:"):
        ref_path_str = head_content[4:].strip()
        branch = ref_path_str.split("/")[-1] if "/" in ref_path_str else ref_path_str

        # Attempt to read direct ref file
        ref_file = git_dir / Path(ref_path_str)
        if ref_file.is_file():
            try:
                commit_hash = ref_file.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                pass

        # Fallback: check .git/packed-refs
        if not commit_hash:
            packed_refs = git_dir / "packed-refs"
            if packed_refs.is_file():
                try:
                    for line in packed_refs.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("^"):
                            parts = line.split()
                            if len(parts) == 2 and parts[1] == ref_path_str:
                                commit_hash = parts[0]
                                break
                except Exception:
                    pass
    elif re.match(r"^[0-9a-fA-F]{40}$", head_content):
        # Detached HEAD with commit SHA directly
        commit_hash = head_content
        branch = "HEAD (detached)"

    return commit_hash, branch


def get_git_metadata(target_dir: Path | str) -> GitMetadata:
    """Extract Git provenance for target repository if available.
    
    Operates safely:
    - Never executes repository hooks or network requests
    - Tries direct file parsing of .git/HEAD first
    - Uses safe subprocess fallback (`--no-optional-locks`) if git CLI is available
    - Gracefully returns empty metadata if not a git repository
    
    Args:
        target_dir: Directory path of the target codebase.
        
    Returns:
        GitMetadata dataclass.
    """
    repo_path = Path(target_dir).resolve()
    git_dir = repo_path / ".git"

    if not git_dir.exists():
        return GitMetadata(is_git_repo=False)

    # Handle git worktrees or submodules where .git is a file
    if git_dir.is_file():
        try:
            content = git_dir.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("gitdir:"):
                git_dir = Path(repo_path, content[7:].strip()).resolve()
        except Exception:
            return GitMetadata(is_git_repo=True)

    # 1. Fast direct file read
    commit_hash, branch = _read_git_dir_directly(git_dir)
    is_dirty: Optional[bool] = None

    # 2. Try safe read-only git command to enrich/verify and check dirty status
    try:
        safe_env = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows"),
        }
        # Get status to check working tree dirty status
        status_proc = subprocess.run(
            ["git", "--no-optional-locks", "status", "--porcelain"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=1.5,
            env=safe_env,
        )
        if status_proc.returncode == 0:
            is_dirty = bool(status_proc.stdout.strip())

        if not commit_hash or not branch:
            rev_proc = subprocess.run(
                ["git", "--no-optional-locks", "rev-parse", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=1.5,
                env=safe_env,
            )
            if rev_proc.returncode == 0:
                commit_hash = rev_proc.stdout.strip()

            branch_proc = subprocess.run(
                ["git", "--no-optional-locks", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=1.5,
                env=safe_env,
            )
            if branch_proc.returncode == 0:
                branch = branch_proc.stdout.strip()
    except Exception:
        # Subprocess failed or timed out; retain file-based values
        pass

    return GitMetadata(
        is_git_repo=True,
        commit_hash=commit_hash,
        branch=branch,
        is_dirty=is_dirty,
    )
