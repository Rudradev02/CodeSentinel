"""Tests for language and framework detection."""

from pathlib import Path
import pytest

from analyzer.detection.frameworks import FrameworkDetector
from analyzer.detection.languages import LanguageDetector
from analyzer.ingestion.discovery import discover_repository_files


@pytest.fixture
def sample_repo_path():
    return Path(__file__).resolve().parent / "fixtures" / "sample_project"


def test_language_detector_by_extension():
    assert LanguageDetector.detect_language("test.py") == "PYTHON"
    assert LanguageDetector.detect_language("script.js") == "JAVASCRIPT"
    assert LanguageDetector.detect_language("component.jsx") == "JAVASCRIPT"
    assert LanguageDetector.detect_language("module.mjs") == "JAVASCRIPT"
    assert LanguageDetector.detect_language("app.ts") == "TYPESCRIPT"
    assert LanguageDetector.detect_language("view.tsx") == "TYPESCRIPT"
    assert LanguageDetector.detect_language("styles.css") == "UNKNOWN"
    assert LanguageDetector.detect_language("readme.md") == "UNKNOWN"


def test_framework_detection_on_sample_project(sample_repo_path):
    files, manifests = discover_repository_files(sample_repo_path)
    detector = FrameworkDetector(sample_repo_path, manifests)
    detected = detector.detect(files)

    framework_names = {fe.framework for fe in detected}
    # Flask declared in requirements.txt and app.py
    assert "flask" in framework_names
    # React declared in package.json and App.tsx / Button.tsx
    assert "react" in framework_names
    # Django is not used in sample_project
    assert "django" not in framework_names

    # Verify evidence lists and confidence
    for fe in detected:
        assert fe.confidence > 0.0
        assert len(fe.evidence) > 0
        if fe.framework == "flask":
            assert any("flask" in ev.lower() for ev in fe.evidence)
        elif fe.framework == "react":
            assert any("react" in ev.lower() or "tsx" in ev.lower() for ev in fe.evidence)
