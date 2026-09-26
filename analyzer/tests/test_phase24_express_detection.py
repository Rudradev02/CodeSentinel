"""Unit tests for Phase 24 Express Framework Detection and Capability Models."""

import pytest
from pathlib import Path
from analyzer.detection.frameworks import FrameworkDetector
from analyzer.frameworks.base import FrameworkModelRegistry, FrameworkCapability


def test_express_detected_from_package_json(tmp_path: Path):
    """Verify FrameworkDetector detects Express from package.json dependencies."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"dependencies": {"express": "^4.18.2", "cors": "^2.8.5"}}', encoding="utf-8")

    app_js = tmp_path / "server.js"
    app_js.write_text("console.log('running');", encoding="utf-8")

    detector = FrameworkDetector()
    detected = detector.detect(tmp_path)
    framework_names = [f.name for f in detected]
    assert "EXPRESS" in framework_names


def test_express_detected_from_source_imports(tmp_path: Path):
    """Verify FrameworkDetector detects Express from require('express') in source files."""
    app_js = tmp_path / "app.js"
    app_js.write_text("const express = require('express');\nconst app = express();", encoding="utf-8")

    detector = FrameworkDetector()
    detected = detector.detect(tmp_path)
    framework_names = [f.name for f in detected]
    assert "EXPRESS" in framework_names


def test_express_framework_capabilities():
    """Verify FrameworkModelRegistry exposes Express capabilities."""
    reg = FrameworkModelRegistry(load_defaults=True)
    adapters = reg.get_applicable_adapters(["EXPRESS"])
    assert len(adapters) > 0

    express_adapter = adapters[0]
    cap = express_adapter.capability
    assert isinstance(cap, FrameworkCapability)
    assert cap.framework_name == "EXPRESS"
    assert cap.supports_routes is True
    assert cap.supports_middleware is True
    assert cap.supports_parameter_binding is True
