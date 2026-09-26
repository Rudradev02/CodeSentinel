"""Evidence-based web framework detection for Django, Flask, and React."""

import json
from pathlib import Path
from typing import Optional

from analyzer.models.metadata import DiscoveredFileMetadata, FrameworkEvidence


class FrameworkDetector:
    """Detects Django, Flask, and React frameworks based on deterministic evidence."""

    def __init__(self, repo_path: Path, manifest_paths: list[Path]):
        self.repo_path = repo_path
        self.manifest_paths = manifest_paths

    def detect(self, files: list[DiscoveredFileMetadata]) -> list[FrameworkEvidence]:
        """Evaluate evidence across manifests and discovered files.
        
        Returns:
            List of FrameworkEvidence objects for detected frameworks.
        """
        frameworks: list[FrameworkEvidence] = []

        # Read manifest contents once
        manifest_text = self._aggregate_manifest_text()
        package_json_data = self._read_package_json()

        # 1. Django Detection
        django_evidence: list[str] = []
        if any(f.name == "manage.py" for f in self.manifest_paths):
            django_evidence.append("manage.py root configuration file present")

        if any("settings.py" in f.relative_path.replace("\\", "/") for f in files):
            django_evidence.append("Django settings module (settings.py) discovered")

        if "django" in manifest_text.lower():
            django_evidence.append("django dependency declared in project requirements/manifest")

        if self._source_contains_tokens(files, ["from django", "import django"], max_checks=25):
            django_evidence.append("Django framework imports found in Python source code")

        if django_evidence:
            confidence = min(0.98, 0.40 + (0.20 * len(django_evidence)))
            frameworks.append(
                FrameworkEvidence(
                    framework="django",
                    confidence=round(confidence, 2),
                    evidence=django_evidence,
                )
            )

        # 2. Flask Detection
        flask_evidence: list[str] = []
        if "flask" in manifest_text.lower():
            flask_evidence.append("flask dependency declared in project requirements/manifest")

        if self._source_contains_tokens(files, ["from flask import", "import flask"], max_checks=25):
            flask_evidence.append("Flask application imports found in Python source code")

        if flask_evidence:
            confidence = min(0.95, 0.45 + (0.25 * len(flask_evidence)))
            frameworks.append(
                FrameworkEvidence(
                    framework="flask",
                    confidence=round(confidence, 2),
                    evidence=flask_evidence,
                )
            )

        # 3. React Detection
        react_evidence: list[str] = []
        if package_json_data:
            deps = package_json_data.get("dependencies", {})
            dev_deps = package_json_data.get("devDependencies", {})
            if "react" in deps or "react" in dev_deps:
                react_evidence.append("react declared in package.json dependencies")
            if "react-dom" in deps or "react-dom" in dev_deps:
                react_evidence.append("react-dom declared in package.json dependencies")

        has_jsx_tsx = any(f.extension in [".jsx", ".tsx"] for f in files)
        if has_jsx_tsx:
            react_evidence.append("JSX/TSX component files present in repository")

        if self._source_contains_tokens(files, ["from 'react'", 'from "react"', "import React"], max_checks=30):
            react_evidence.append("React module imports detected in JavaScript/TypeScript source")

        if react_evidence:
            confidence = min(0.98, 0.40 + (0.20 * len(react_evidence)))
            frameworks.append(
                FrameworkEvidence(
                    framework="react",
                    confidence=round(confidence, 2),
                    evidence=react_evidence,
                )
            )

        # 4. Express Detection
        express_evidence: list[str] = []
        if package_json_data:
            deps = package_json_data.get("dependencies", {})
            dev_deps = package_json_data.get("devDependencies", {})
            if "express" in deps or "express" in dev_deps:
                express_evidence.append("express declared in package.json dependencies")

        if "express" in manifest_text.lower():
            express_evidence.append("express dependency declared in project manifest")

        if self._source_contains_tokens(
            files,
            ["require('express')", 'require("express")', "from 'express'", 'from "express"'],
            max_checks=30,
        ):
            express_evidence.append("Express module imports/requires detected in JavaScript/TypeScript source")

        if express_evidence:
            confidence = min(0.98, 0.40 + (0.25 * len(express_evidence)))
            frameworks.append(
                FrameworkEvidence(
                    framework="express",
                    confidence=round(confidence, 2),
                    evidence=express_evidence,
                )
            )

        return frameworks

    def _aggregate_manifest_text(self) -> str:
        """Combine readable text across Python and Node manifests."""
        combined = []
        for p in self.manifest_paths:
            if p.suffix.lower() in [".txt", ".toml", ".json", ""]:
                try:
                    combined.append(p.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    pass
        return " ".join(combined)

    def _read_package_json(self) -> Optional[dict]:
        """Read and parse root package.json if present."""
        for p in self.manifest_paths:
            if p.name.lower() == "package.json":
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        return json.load(f)
                except Exception:
                    return None
        return None

    def _source_contains_tokens(
        self,
        files: list[DiscoveredFileMetadata],
        tokens: list[str],
        max_checks: int = 25,
    ) -> bool:
        """Sample discovered source files to check for presence of signature tokens."""
        checked = 0
        for f in files:
            if checked >= max_checks:
                break
            try:
                # Read head of file
                with open(f.path, "r", encoding="utf-8", errors="ignore") as file_obj:
                    sample = file_obj.read(4096)
                    if any(t in sample for t in tokens):
                        return True
                checked += 1
            except Exception:
                continue
        return False
