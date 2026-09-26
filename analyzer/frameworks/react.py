"""React framework semantic adapter for CodeSentinel (Phase 23)."""

from __future__ import annotations

import re
from typing import Any, Optional
from analyzer.frameworks.base import BaseFrameworkAdapter
from analyzer.models.boundary import (
    AuthenticationState,
    AuthorizationState,
    TrustBoundaryEvidence,
    TrustBoundaryType,
)
from analyzer.models.parse import ParsedFile


class ReactAdapter(BaseFrameworkAdapter):
    """Semantic adapter for React client-side applications."""

    @property
    def framework_name(self) -> str:
        return "REACT"

    def extract_trust_boundaries(
        self,
        parsed_file: ParsedFile,
        ast_tree: Optional[Any] = None,
        file_content: str = "",
    ) -> list[TrustBoundaryEvidence]:
        boundaries: list[TrustBoundaryEvidence] = []
        if parsed_file.language not in ("JAVASCRIPT", "TYPESCRIPT"):
            return boundaries

        # Scan for React Router hooks: useSearchParams, useParams, useLocation
        lines = file_content.splitlines() if file_content else []
        for line_idx, line in enumerate(lines, start=1):
            if "useSearchParams(" in line:
                boundaries.append(
                    TrustBoundaryEvidence(
                        boundary_id=f"TB_REACT_SEARCH_PARAMS_{line_idx}",
                        boundary_type=TrustBoundaryType.HTTP_REQUEST_PARAM,
                        framework="REACT",
                        file_path=parsed_file.file_path,
                        line=line_idx,
                        column=line.find("useSearchParams"),
                        symbol_name="useSearchParams()",
                        is_authenticated=AuthenticationState.UNKNOWN,
                        is_authorized=AuthorizationState.UNKNOWN,
                        boundary_confidence="HIGH",
                        details="React router search params hook useSearchParams()",
                    )
                )
            elif "useParams(" in line:
                boundaries.append(
                    TrustBoundaryEvidence(
                        boundary_id=f"TB_REACT_PARAMS_{line_idx}",
                        boundary_type=TrustBoundaryType.HTTP_REQUEST_PARAM,
                        framework="REACT",
                        file_path=parsed_file.file_path,
                        line=line_idx,
                        column=line.find("useParams"),
                        symbol_name="useParams()",
                        is_authenticated=AuthenticationState.UNKNOWN,
                        is_authorized=AuthorizationState.UNKNOWN,
                        boundary_confidence="HIGH",
                        details="React router route params hook useParams()",
                    )
                )

        return boundaries

    def extract_authentication_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> AuthenticationState:
        return AuthenticationState.UNKNOWN

    def extract_authorization_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> tuple[AuthorizationState, Optional[str]]:
        return (AuthorizationState.UNKNOWN, None)
