"""Repository ingestion, file discovery, and exclusion rule matching."""

from analyzer.ingestion.discovery import discover_repository_files
from analyzer.ingestion.ignore import IgnoreEngine, IngestionConfig
from analyzer.ingestion.repository import validate_repository_path

__all__ = [
    "validate_repository_path",
    "IngestionConfig",
    "IgnoreEngine",
    "discover_repository_files",
]
