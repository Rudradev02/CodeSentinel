"""Phase 15 architectural decoupling and boundary independence tests."""

import ast
from pathlib import Path

ANALYZER_ROOT = Path(__file__).resolve().parent.parent.parent / "analyzer"

FORBIDDEN_MODULES = {
    "backend",
    "openrouter",
    "ollama",
    "httpx",
    "celery",
    "redis",
    "fastapi",
    "sqlalchemy",
    "alembic",
    "ai_enrichment",
}


def test_analyzer_phase15_modules_have_zero_backend_imports():
    """Verify analyzer/dataflow/callgraph, analyzer/dataflow/interprocedural, and all Phase 15 modules have ZERO forbidden imports."""
    violations = []

    for py_file in ANALYZER_ROOT.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in FORBIDDEN_MODULES:
                        violations.append((str(py_file), alias.name))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in FORBIDDEN_MODULES:
                        violations.append((str(py_file), node.module))

    assert not violations, f"Forbidden backend/infrastructure imports found in analyzer/: {violations}"
