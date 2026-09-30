"""Registry for managing polyglot language adapters."""

from typing import Dict, Optional
from analyzer.adapters.base import BaseLanguageAdapter

class LanguageAdapterRegistry:
    """Registry for discovering and dispensing language adapters."""
    
    def __init__(self) -> None:
        self._adapters: dict[str, BaseLanguageAdapter] = {}
        
    def register(self, adapter: BaseLanguageAdapter) -> None:
        """Register a language adapter instance."""
        self._adapters[adapter.language_id] = adapter
        
    def get_adapter(self, language_id: str) -> Optional[BaseLanguageAdapter]:
        """Retrieve an adapter by its canonical language ID."""
        return self._adapters.get(language_id)
        
    def get_all(self) -> dict[str, BaseLanguageAdapter]:
        """Return all registered adapters."""
        return dict(self._adapters)
