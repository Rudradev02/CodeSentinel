"""CodeSentinel Backend Application Package."""

import sys
from pathlib import Path

# Ensure repository root is on sys.path so 'backend' package imports resolve seamlessly
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

__version__ = "0.1.0"
