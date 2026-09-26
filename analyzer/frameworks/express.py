"""Express.js framework semantic adapter for CodeSentinel (Phase 23)."""

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
from analyzer.models.parser import ParsedFile


class ExpressAdapter(BaseFrameworkAdapter):
    """Semantic adapter for Express.js server applications."""

    @property
    def framework_name(self) -> str:
        return "EXPRESS"

    def extract_trust_boundaries(
        self,
        parsed_file: ParsedFile,
        ast_tree: Optional[Any] = None,
        file_content: str = "",
    ) -> list[TrustBoundaryEvidence]:
        boundaries: list[TrustBoundaryEvidence] = []
        if parsed_file.language not in ("JAVASCRIPT", "TYPESCRIPT"):
            return boundaries

        lines = file_content.splitlines() if file_content else []
        for line_idx, line in enumerate(lines, start=1):
            for prop, b_type in [
                ("req.query", TrustBoundaryType.HTTP_REQUEST_PARAM),
                ("req.params", TrustBoundaryType.HTTP_REQUEST_PARAM),
                ("req.body", TrustBoundaryType.HTTP_REQUEST_BODY),
                ("req.headers", TrustBoundaryType.HTTP_REQUEST_HEADER),
                ("req.cookies", TrustBoundaryType.HTTP_COOKIE),
            ]:
                if prop in line:
                    boundaries.append(
                        TrustBoundaryEvidence(
                            boundary_id=f"TB_EXPRESS_{prop.replace('.', '_').upper()}_{line_idx}",
                            boundary_type=b_type,
                            framework="EXPRESS",
                            file_path=parsed_file.file_path,
                            line=line_idx,
                            column=line.find(prop),
                            symbol_name=prop,
                            is_authenticated=AuthenticationState.UNKNOWN,
                            is_authorized=AuthorizationState.UNKNOWN,
                            boundary_confidence="HIGH",
                            details=f"Express request property access {prop}",
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
