"""Deterministic language detection based on file extensions and manifest signals."""

from pathlib import Path
from typing import Optional

from analyzer.models.metadata import DiscoveredFileMetadata

LANGUAGE_EXTENSION_MAP = {
    ".py": "PYTHON",
    ".js": "JAVASCRIPT",
    ".jsx": "JAVASCRIPT",
    ".mjs": "JAVASCRIPT",
    ".cjs": "JAVASCRIPT",
    ".ts": "TYPESCRIPT",
    ".tsx": "TYPESCRIPT",
}


class LanguageDetector:
    """Classifies source files into supported programming language categories."""

    @staticmethod
    def detect_language(path: Path | str) -> str:
        """Determine language from file extension.
        
        Returns:
            'PYTHON', 'JAVASCRIPT', 'TYPESCRIPT', or 'UNKNOWN'
        """
        ext = Path(path).suffix.lower()
        return LANGUAGE_EXTENSION_MAP.get(ext, "UNKNOWN")

    @staticmethod
    def calculate_distribution(files: list[DiscoveredFileMetadata]) -> dict[str, int]:
        """Aggregate file counts grouped by language."""
        counts: dict[str, int] = {}
        for f in files:
            lang = f.language
            counts[lang] = counts.get(lang, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))

    @staticmethod
    def calculate_loc_distribution(files: list[DiscoveredFileMetadata]) -> dict[str, int]:
        """Aggregate lines of code grouped by language."""
        loc_counts: dict[str, int] = {}
        for f in files:
            lang = f.language
            loc_counts[lang] = loc_counts.get(lang, 0) + f.line_count
        return dict(sorted(loc_counts.items(), key=lambda item: item[1], reverse=True))
