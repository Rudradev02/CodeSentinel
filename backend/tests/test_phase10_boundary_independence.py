"""Tests for architectural boundary independence: Analyzer remains 100% database-independent."""

import ast
from pathlib import Path

ANALYZER_DIR = Path(__file__).resolve().parent.parent.parent / "analyzer"

FORBIDDEN_IMPORTS = {
    "backend",
    "sqlalchemy",
    "alembic",
    "asyncpg",
    "aiosqlite",
    "fastapi",
    "starlette",
    "celery",
    "redis",
    "openrouter",
    "ollama",
    "openai",
    "anthropic",
}


def test_analyzer_has_zero_backend_or_database_imports():
    """Verify that analyzer/ directory has zero dependencies on backend or database packages."""
    violations: list[str] = []

    for py_file in ANALYZER_DIR.rglob("*.py"):
        # Skip tests or virtual envs if any
        if "tests" in py_file.parts or "__pycache__" in py_file.parts:
            continue

        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in FORBIDDEN_IMPORTS:
                        violations.append(f"{py_file.relative_to(ANALYZER_DIR)} imports forbidden '{alias.name}'")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in FORBIDDEN_IMPORTS:
                        violations.append(f"{py_file.relative_to(ANALYZER_DIR)} imports from forbidden '{node.module}'")

    assert not violations, f"Architectural Invariant Violation: analyzer/ contains forbidden imports:\n" + "\n".join(violations)
