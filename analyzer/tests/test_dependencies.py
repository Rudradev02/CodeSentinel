"""Tests for dependency resolution, category classification, and unresolved imports."""

from pathlib import Path
import pytest

from analyzer.dependencies.resolver import DependencyResolver
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.models.parse import ImportCategory
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_dependency_resolution_python(sample_repo_path):
    files, _ = discover_repository_files(sample_repo_path)
    py_parser = PythonParser()
    app_py = sample_repo_path / "backend" / "app.py"
    parsed = py_parser.parse(app_py, "backend/app.py", app_py.read_text(encoding="utf-8"))

    resolver = DependencyResolver(files)
    resolver.resolve_all([parsed])

    import_map = {imp.source_module: imp for imp in parsed.imports}

    # os, sys -> STDLIB
    assert import_map["os"].dependency_category == ImportCategory.STDLIB
    assert import_map["sys"].dependency_category == ImportCategory.STDLIB

    # flask -> EXTERNAL
    assert import_map["flask"].dependency_category == ImportCategory.EXTERNAL

    # services.user_service -> LOCAL (resolves to backend/services/user_service.py)
    user_svc_imp = import_map["services.user_service"]
    assert user_svc_imp.dependency_category == ImportCategory.LOCAL
    assert user_svc_imp.resolved_path == "backend/services/user_service.py"


def test_dependency_resolution_typescript(sample_repo_path):
    files, _ = discover_repository_files(sample_repo_path)
    ts_parser = TypeScriptParser()
    app_tsx = sample_repo_path / "frontend" / "App.tsx"
    parsed = ts_parser.parse(app_tsx, "frontend/App.tsx", app_tsx.read_text(encoding="utf-8"))

    resolver = DependencyResolver(files)
    resolver.resolve_all([parsed])

    import_map = {imp.source_module: imp for imp in parsed.imports}

    # react -> EXTERNAL
    assert import_map["react"].dependency_category == ImportCategory.EXTERNAL

    # ./components/Button -> LOCAL (resolves to frontend/components/Button.tsx)
    button_imp = import_map["./components/Button"]
    assert button_imp.dependency_category == ImportCategory.LOCAL
    assert button_imp.resolved_path == "frontend/components/Button.tsx"

    # ./utils/api -> LOCAL (resolves to frontend/utils/api.ts)
    api_imp = import_map["./utils/api"]
    assert api_imp.dependency_category == ImportCategory.LOCAL
    assert api_imp.resolved_path == "frontend/utils/api.ts"


def test_unresolved_import_not_discarded(sample_repo_path):
    files, _ = discover_repository_files(sample_repo_path)
    ts_parser = TypeScriptParser()
    code = "import { Missing } from './non_existent_component';"
    parsed = ts_parser.parse(Path("/dummy/file.tsx"), "frontend/dummy.tsx", code)

    resolver = DependencyResolver(files)
    resolver.resolve_all([parsed])

    assert len(parsed.imports) == 1
    imp = parsed.imports[0]
    # Unresolved import MUST remain visible as UNRESOLVED
    assert imp.dependency_category == ImportCategory.UNRESOLVED
    assert imp.resolved_path is None
