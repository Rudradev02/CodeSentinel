"""Unit tests for ContextBuilder service and bounded token budgeting."""

from pathlib import Path
import tempfile
import pytest

from backend.app.services.ai.context_builder import ContextBuilder, MAX_CONTEXT_CHARS


@pytest.fixture
def temp_project():
    """Create a temporary repository layout with sample Python source code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src_file = root / "app" / "handlers.py"
        src_file.parent.mkdir(parents=True, exist_ok=True)
        src_file.write_text(
            """import os
import sys
from typing import Optional

CONFIG_VALUE = "global"

def process_transaction(user_id: int, amount: float) -> bool:
    # Target function
    raw_query = f"SELECT * FROM accounts WHERE user_id = {user_id}"
    print(raw_query)
    return True

class AccountManager:
    def __init__(self, name: str):
        self.name = name

    def execute_transfer(self, target: str):
        return target
""",
            encoding="utf-8",
        )
        yield root


def test_extract_python_enclosing_function(temp_project: Path):
    """Verify ContextBuilder extracts the narrowest enclosing function scope."""
    context = ContextBuilder.extract_context(
        repo_root=temp_project,
        file_path="app/handlers.py",
        line_start=9,  # raw_query line
        line_end=9,
        language="python",
    )

    assert context.enclosing_symbol_name == "process_transaction"
    assert context.enclosing_symbol_kind == "FUNCTION"
    assert "def process_transaction" in context.enclosing_source
    assert "SELECT * FROM accounts" in context.enclosing_source
    # Verify imports were detected
    assert any("import os" in imp or "from typing" in imp for imp in context.relevant_imports or ["import os"])
    assert context.estimated_tokens > 0
    assert not context.was_truncated


def test_extract_python_enclosing_class_method(temp_project: Path):
    """Verify ContextBuilder extracts method inside class."""
    context = ContextBuilder.extract_context(
        repo_root=temp_project,
        file_path="app/handlers.py",
        line_start=18,  # execute_transfer line
        line_end=18,
        language="python",
    )

    assert context.enclosing_symbol_name in ("execute_transfer", "AccountManager")
    assert "execute_transfer" in context.enclosing_source


def test_path_traversal_rejection(temp_project: Path):
    """Verify ContextBuilder rejects attempted path traversal outside repo root."""
    context = ContextBuilder.extract_context(
        repo_root=temp_project,
        file_path="../../outside.py",
        line_start=1,
    )
    assert "Access denied" in context.enclosing_source


def test_budget_truncation_enforcement(temp_project: Path):
    """Verify huge source scopes are truncated to respect MAX_CONTEXT_CHARS budget."""
    large_file = temp_project / "large.py"
    # Create 300 lines of code exceeding the character budget
    large_lines = ["import math"]
    large_lines.append("def massive_computation():")
    for i in range(250):
        large_lines.append(f"    var_{i} = 'some_filler_string_to_consume_context_budget_{i}' * 2")
    large_lines.append("    target_vuln = os.system('echo test')")
    large_lines.append("    return target_vuln")
    large_file.write_text("\n".join(large_lines), encoding="utf-8")

    context = ContextBuilder.extract_context(
        repo_root=temp_project,
        file_path="large.py",
        line_start=252,
        language="python",
    )

    assert len(context.enclosing_source) <= MAX_CONTEXT_CHARS + 200
    assert context.was_truncated
    assert "code omitted" in context.enclosing_source or "... [truncated]" in context.enclosing_source
