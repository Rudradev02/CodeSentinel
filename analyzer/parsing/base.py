"""Base parser interface for CodeSentinel AST parsing."""

from abc import ABC, abstractmethod
from pathlib import Path

from analyzer.models.parse import ParsedFile


class BaseParser(ABC):
    """Abstract contract for language-specific syntax tree parsers.
    
    All language parsers normalize syntax trees into the standard ParsedFile schema.
    """

    @abstractmethod
    def parse(self, file_path: Path, relative_path: str, content: str) -> ParsedFile:
        """Parse source code string into a normalized ParsedFile representation.
        
        Args:
            file_path: Absolute path to the source file on disk.
            relative_path: Forward-slash normalized path relative to repo root.
            content: Raw string content of the source file.
            
        Returns:
            Populated ParsedFile instance. Malformed code must be represented
            with success=False and populated errors rather than raising uncaught exceptions.
        """
        pass
