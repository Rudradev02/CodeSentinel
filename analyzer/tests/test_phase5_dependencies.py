"""Phase 5 tests for dependency classification semantics."""

from pathlib import Path
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.models.parse import ImportCategory
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser


def test_python_dependency_classification_all_categories():
    """Verify Python imports are cleanly separated into STDLIB, EXTERNAL, LOCAL, and UNRESOLVED."""
    py_parser = PythonParser()
    sample_path = Path(__file__).resolve().parent / "fixtures" / "sample_project"
    files, _ = discover_repository_files(sample_path)
    resolver = DependencyResolver(files)

    code = """
import os
import sys
import flask
from services.user_service import get_user
from .non_existent_relative import Missing
"""
    parsed = py_parser.parse(sample_path / "backend" / "app.py", "backend/app.py", code)
    resolver.resolve_all([parsed])

    import_map = {imp.source_module: imp for imp in parsed.imports}

    # 1. STDLIB
    assert import_map["os"].dependency_category == ImportCategory.STDLIB
    assert import_map["sys"].dependency_category == ImportCategory.STDLIB

    # 2. EXTERNAL
    assert import_map["flask"].dependency_category == ImportCategory.EXTERNAL

    # 3. LOCAL
    assert import_map["services.user_service"].dependency_category == ImportCategory.LOCAL
    assert import_map["services.user_service"].resolved_path == "backend/services/user_service.py"

    # 4. UNRESOLVED (missing relative import must NOT become EXTERNAL)
    assert import_map[".non_existent_relative"].dependency_category == ImportCategory.UNRESOLVED
    assert import_map[".non_existent_relative"].resolved_path is None


def test_typescript_dependency_classification_all_categories():
    """Verify JS/TS imports are cleanly separated into STDLIB, EXTERNAL, LOCAL, and UNRESOLVED."""
    ts_parser = TypeScriptParser()
    sample_path = Path(__file__).resolve().parent / "fixtures" / "sample_project"
    files, _ = discover_repository_files(sample_path)
    resolver = DependencyResolver(files)

    code = """
import fs from 'fs';
import path from 'node:path';
import React from 'react';
import { Button } from './components/Button';
import { Unknown } from './components/NonExistent';
"""
    parsed = ts_parser.parse(sample_path / "frontend" / "App.tsx", "frontend/App.tsx", code)
    resolver.resolve_all([parsed])

    import_map = {imp.source_module: imp for imp in parsed.imports}

    # 1. STDLIB (Node built-ins)
    assert import_map["fs"].dependency_category == ImportCategory.STDLIB
    assert import_map["node:path"].dependency_category == ImportCategory.STDLIB

    # 2. EXTERNAL
    assert import_map["react"].dependency_category == ImportCategory.EXTERNAL

    # 3. LOCAL
    assert import_map["./components/Button"].dependency_category == ImportCategory.LOCAL
    assert import_map["./components/Button"].resolved_path == "frontend/components/Button.tsx"

    # 4. UNRESOLVED
    assert import_map["./components/NonExistent"].dependency_category == ImportCategory.UNRESOLVED
    assert import_map["./components/NonExistent"].resolved_path is None
