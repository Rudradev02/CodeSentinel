"""Tests for Python AST and Tree-sitter JavaScript/TypeScript parsers."""

from pathlib import Path
import pytest

from analyzer.parsing.javascript_parser import JavaScriptParser
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_python_parser_valid_file(sample_repo_path):
    parser = PythonParser()
    app_py = sample_repo_path / "backend" / "app.py"
    content = app_py.read_text(encoding="utf-8")

    parsed = parser.parse(app_py, "backend/app.py", content)
    assert parsed.success is True
    assert parsed.language == "PYTHON"
    assert len(parsed.errors) == 0

    # Verify imports
    import_sources = [imp.source_module for imp in parsed.imports]
    assert "os" in import_sources
    assert "sys" in import_sources
    assert "flask" in import_sources
    assert "services.user_service" in import_sources

    # Verify symbols
    symbol_names = [sym.name for sym in parsed.symbols]
    assert "user_detail" in symbol_names


def test_python_parser_malformed_syntax(sample_repo_path):
    parser = PythonParser()
    broken_py = sample_repo_path / "broken.py"
    content = broken_py.read_text(encoding="utf-8")

    parsed = parser.parse(broken_py, "broken.py", content)
    # Must capture error without raising unhandled exception
    assert parsed.success is False
    assert len(parsed.errors) > 0
    assert parsed.errors[0].error_type == "SYNTAX_ERROR"
    assert parsed.errors[0].line is not None


def test_javascript_parser():
    parser = JavaScriptParser()
    code = """
    import React, { useState } from 'react';
    import { add } from './math';
    const utils = require('./utils');
    
    export function calculate(a, b) {
        return add(a, b);
    }
    export default class Calculator {}
    """
    file_path = Path("/dummy/calc.js")
    parsed = parser.parse(file_path, "calc.js", code)

    assert parsed.success is True
    assert parsed.language == "JAVASCRIPT"
    assert len(parsed.imports) == 3

    sources = [imp.source_module for imp in parsed.imports]
    assert "react" in sources
    assert "./math" in sources
    assert "./utils" in sources

    export_names = [exp.name for exp in parsed.exports]
    assert "calculate" in export_names
    assert "Calculator" in export_names


def test_typescript_parser_with_tsx(sample_repo_path):
    parser = TypeScriptParser()
    button_tsx = sample_repo_path / "frontend" / "components" / "Button.tsx"
    content = button_tsx.read_text(encoding="utf-8")

    parsed = parser.parse(button_tsx, "frontend/components/Button.tsx", content)
    assert parsed.success is True
    assert parsed.language == "TYPESCRIPT"
    assert len(parsed.errors) == 0

    # Imports
    assert any(imp.source_module == "react" for imp in parsed.imports)

    # Exports
    export_names = [exp.name for exp in parsed.exports]
    assert "Button" in export_names
    assert "ButtonProps" in export_names


def test_typescript_parser_types_and_interfaces():
    parser = TypeScriptParser()
    code = """
    import type { Config } from './config';
    export interface User { id: number; }
    export type ID = string | number;
    export function getUser(): User { return { id: 1 }; }
    """
    file_path = Path("/dummy/types.ts")
    parsed = parser.parse(file_path, "types.ts", code)

    assert parsed.success is True
    assert parsed.language == "TYPESCRIPT"
    assert len(parsed.imports) == 1
    assert parsed.imports[0].import_type.value == "TYPE_ONLY"

    symbols = {s.name: s.kind.value for s in parsed.symbols}
    assert symbols.get("User") == "INTERFACE"
    assert symbols.get("ID") == "TYPE_ALIAS"
    assert symbols.get("getUser") == "FUNCTION"
