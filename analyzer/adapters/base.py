"""Base adapter and capabilities for polyglot language support."""

from abc import abstractmethod
from enum import Enum

from analyzer.parsing.base import BaseParser

class LanguageCapability(str, Enum):
    """Capabilities that a specific language adapter might support."""
    AST_PARSING = "AST_PARSING"
    MODULE_RESOLUTION = "MODULE_RESOLUTION"
    CONTRACT_EXTRACTION = "CONTRACT_EXTRACTION"
    SECURITY_ANALYSIS = "SECURITY_ANALYSIS"


class BaseLanguageAdapter(BaseParser):
    """Contract for language adapters, extending basic AST parsing with discovery of capabilities."""

    @property
    @abstractmethod
    def language_id(self) -> str:
        """Standard canonical identifier for the language (e.g., 'PYTHON', 'JAVASCRIPT', 'GO')."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> set[LanguageCapability]:
        """Capabilities supported by this specific language adapter."""
        pass
