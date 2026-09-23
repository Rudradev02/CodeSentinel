"""Phase 11 Architectural Boundary Invariant Test.

Enforces zero-leakage decoupling: the analyzer/ package must contain
ZERO imports of celery, redis, kombu, sse_starlette, sqlalchemy, psycopg2, fastapi, or starlette.
The analyzer engine must remain 100% offline, standalone, and infrastructure-independent.
"""

import ast
from pathlib import Path

FORBIDDEN_PACKAGES = {
    "celery",
    "kombu",
    "billiard",
    "redis",
    "sse_starlette",
    "sqlalchemy",
    "alembic",
    "psycopg2",
    "asyncpg",
    "aiosqlite",
    "fastapi",
    "starlette",
    "uvicorn",
    "backend",
}


def test_analyzer_has_zero_phase11_infrastructure_imports():
    """Verify via AST parsing that analyzer/ has zero infrastructure or worker imports."""
    analyzer_dir = Path(__file__).resolve().parent.parent.parent / "analyzer"
    assert analyzer_dir.is_dir(), f"Analyzer directory not found at {analyzer_dir}"

    python_files = list(analyzer_dir.rglob("*.py"))
    assert len(python_files) > 10, f"Expected analyzer python files, found {len(python_files)}"

    violations: list[str] = []

    for py_file in python_files:
        # Skip pycache and hidden
        if "__pycache__" in py_file.parts or ".pytest_cache" in py_file.parts:
            continue

        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in FORBIDDEN_PACKAGES:
                        violations.append(
                            f"{py_file.relative_to(analyzer_dir)}:{node.lineno} imports '{alias.name}'"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in FORBIDDEN_PACKAGES:
                        violations.append(
                            f"{py_file.relative_to(analyzer_dir)}:{node.lineno} from '{node.module}' import ..."
                        )

    assert not violations, (
        f"CRITICAL BOUNDARY VIOLATION: Analyzer must NOT import backend infrastructure!\n"
        f"Violations found:\n" + "\n".join(violations)
    )
