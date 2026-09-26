"""Base framework adapter and registry for CodeSentinel (Phase 23)."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import Any, Optional
from analyzer.models.boundary import (
    AuthenticationState,
    AuthorizationState,
    TrustBoundaryEvidence,
    TrustBoundaryType,
)
from analyzer.models.parse import ParsedFile


from pydantic import BaseModel, ConfigDict, Field


class FrameworkCapability(BaseModel):
    """Declared capabilities, detection patterns, and version constraints of a framework adapter."""
    model_config = ConfigDict(frozen=True)

    framework_id: str
    display_name: str
    supports_route_extraction: bool = True
    supports_path_parameters: bool = True
    supports_request_body: bool = True
    supports_authentication_extraction: bool = True
    supports_authorization_extraction: bool = True
    supported_versions: str = ">=1.0.0"
    detection_manifest_tokens: list[str] = Field(default_factory=list)
    detection_source_tokens: list[str] = Field(default_factory=list)


class BaseFrameworkAdapter(ABC):
    """Abstract base class for framework-specific AST boundary and security adapters."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Name of the framework (e.g. 'FLASK', 'DJANGO', 'REACT', 'EXPRESS')."""
        pass

    @property
    def capability(self) -> FrameworkCapability:
        """Metadata describing supported capabilities of this framework adapter."""
        return FrameworkCapability(
            framework_id=self.framework_name,
            display_name=self.framework_name.capitalize(),
        )

    @abstractmethod
    def extract_trust_boundaries(
        self,
        parsed_file: ParsedFile,
        ast_tree: Optional[Any] = None,
        file_content: str = "",
    ) -> list[TrustBoundaryEvidence]:
        """Extract explicit trust boundaries from source AST."""
        pass

    @abstractmethod
    def extract_authentication_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> AuthenticationState:
        """Evaluate evidence-based authentication state for a function definition."""
        pass

    @abstractmethod
    def extract_authorization_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> tuple[AuthorizationState, Optional[str]]:
        """Evaluate evidence-based authorization state and permission string for a function definition."""
        pass


class FrameworkModelRegistry:
    """Registry maintaining available framework adapters."""

    def __init__(self, load_defaults: bool = True):
        self._adapters: dict[str, BaseFrameworkAdapter] = {}
        if load_defaults:
            self._load_defaults()

    def register(self, adapter: BaseFrameworkAdapter) -> None:
        self._adapters[adapter.framework_name.upper()] = adapter

    def get_adapter(self, framework_name: str) -> Optional[BaseFrameworkAdapter]:
        return self._adapters.get(framework_name.upper())

    def get_applicable_adapters(self, detected_frameworks: list[str]) -> list[BaseFrameworkAdapter]:
        active = []
        for df in detected_frameworks:
            ad = self.get_adapter(df)
            if ad:
                active.append(ad)
        return active

    def get_all_adapters(self) -> list[BaseFrameworkAdapter]:
        return list(self._adapters.values())

    def _load_defaults(self) -> None:
        from analyzer.frameworks.flask import FlaskAdapter
        from analyzer.frameworks.django import DjangoAdapter
        from analyzer.frameworks.react import ReactAdapter
        from analyzer.frameworks.express import ExpressAdapter

        self.register(FlaskAdapter())
        self.register(DjangoAdapter())
        self.register(ReactAdapter())
        self.register(ExpressAdapter())
