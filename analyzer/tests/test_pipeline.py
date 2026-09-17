"""End-to-end integration tests for the full AnalysisPipeline."""

import json
from pathlib import Path
import pytest

from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.results import AnalysisResult, AnalysisStatus


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_pipeline_end_to_end(sample_repo_path):
    pipeline = AnalysisPipeline()
    result = pipeline.run(sample_repo_path, repository_name="Sample Project")

    # 1. Result and status
    assert isinstance(result, AnalysisResult)
    assert result.status == AnalysisStatus.COMPLETED
    assert result.repository.name == "Sample Project"

    # 2. File discovery
    rel_paths = {f.relative_path.replace("\\", "/") for f in result.files}
    assert len(rel_paths) >= 7
    assert "backend/app.py" in rel_paths
    assert "frontend/App.tsx" in rel_paths
    assert "broken.py" in rel_paths
    assert "ignored/ignored.py" not in rel_paths

    # 3. Language detection
    assert "PYTHON" in result.repository.detected_languages
    assert "TYPESCRIPT" in result.repository.detected_languages

    # 4. Framework detection
    assert "flask" in result.repository.detected_frameworks
    assert "react" in result.repository.detected_frameworks
    assert "django" not in result.repository.detected_frameworks
    assert len(result.framework_details) >= 2

    # 5. Resilience to malformed files (broken.py)
    error_files = {pe.file_path.replace("\\", "/") for pe in result.parsing_errors}
    assert "broken.py" in error_files

    # 6. Cycle detection
    assert len(result.graph.circular_dependencies) >= 1
    cycle_modules_sets = [set(c.modules) for c in result.graph.circular_dependencies]
    assert {"backend/services/user_service.py", "backend/models/user.py"} in cycle_modules_sets

    # 7. Architecture metrics
    assert result.graph.metrics.total_modules == len(rel_paths)
    assert result.graph.metrics.circular_cycles_count >= 1

    # 8. Timing metadata
    assert result.metadata.duration_seconds is not None
    assert result.metadata.duration_seconds >= 0.0

    # 9. JSON serialization round-trip
    json_output = result.model_dump_json()
    assert len(json_output) > 500

    loaded = AnalysisResult.model_validate_json(json_output)
    assert loaded.repository.name == result.repository.name
    assert loaded.repository.total_files == result.repository.total_files
    assert len(loaded.graph.circular_dependencies) == len(result.graph.circular_dependencies)


def test_pipeline_invalid_path():
    pipeline = AnalysisPipeline()
    with pytest.raises(FileNotFoundError):
        pipeline.run(Path("/non/existent/path/for/sure"))


def test_analyzer_package_independence():
    """Verify that analyzer does not import any web, DB, queue, or backend modules."""
    from pathlib import Path

    analyzer_dir = Path(__file__).resolve().parent.parent
    forbidden_tokens = ["fastapi", "celery", "sqlalchemy", "redis", "backend.", "httpx"]

    for py_file in analyzer_dir.rglob("*.py"):
        if "tests" in py_file.parts:
            continue
        content = py_file.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content.lower(), f"Forbidden token '{token}' found in {py_file}"
        assert "import requests" not in content, f"Forbidden import requests found in {py_file}"
        assert "from requests" not in content, f"Forbidden from requests found in {py_file}"
