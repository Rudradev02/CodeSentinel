"""Unit tests for Phase 24 Express Framework Detection and Capability Models."""

import pytest
from pathlib import Path
from analyzer.detection.frameworks import FrameworkDetector
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.frameworks.base import FrameworkModelRegistry, FrameworkCapability


def test_express_detected_from_package_json(tmp_path: Path):
    """Verify FrameworkDetector detects Express from package.json dependencies."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"dependencies": {"express": "^4.18.2", "cors": "^2.8.5"}}', encoding="utf-8")

    app_js = tmp_path / "server.js"
    app_js.write_text("console.log('running');", encoding="utf-8")

    files = [
        DiscoveredFileMetadata(
            path=str(app_js),
            relative_path="server.js",
            extension=".js",
            language="JAVASCRIPT",
        )
    ]
    detector = FrameworkDetector(repo_path=tmp_path, manifest_paths=[pkg_json])
    detected = detector.detect(files)
    framework_names = [f.framework.lower() for f in detected]
    assert "express" in framework_names


def test_express_detected_from_source_imports(tmp_path: Path):
    """Verify FrameworkDetector detects Express from require('express') in source files."""
    app_js = tmp_path / "app.js"
    app_js.write_text("const express = require('express');\nconst app = express();", encoding="utf-8")

    files = [
        DiscoveredFileMetadata(
            path=str(app_js),
            relative_path="app.js",
            extension=".js",
            language="JAVASCRIPT",
        )
    ]
    detector = FrameworkDetector(repo_path=tmp_path, manifest_paths=[])
    detected = detector.detect(files)
    framework_names = [f.framework.lower() for f in detected]
    assert "express" in framework_names


def test_express_framework_capabilities():
    """Verify FrameworkModelRegistry exposes Express capabilities."""
    reg = FrameworkModelRegistry(load_defaults=True)
    adapters = reg.get_applicable_adapters(["EXPRESS"])
    assert len(adapters) > 0

    express_adapter = adapters[0]
    cap = express_adapter.capability
    assert isinstance(cap, FrameworkCapability)
    assert cap.framework_id == "EXPRESS"
    assert cap.supports_route_extraction is True
    assert cap.supports_authentication_extraction is True
    assert cap.supports_authorization_extraction is True
