"""Django framework semantic adapter for CodeSentinel (Phase 23)."""

from __future__ import annotations

import ast
from typing import Any, Optional
from analyzer.frameworks.base import BaseFrameworkAdapter
from analyzer.models.boundary import (
    AuthenticationState,
    AuthorizationState,
    TrustBoundaryEvidence,
    TrustBoundaryType,
)
from analyzer.models.parser import ParsedFile


class DjangoAdapter(BaseFrameworkAdapter):
    """Semantic adapter for Django web applications."""

    @property
    def framework_name(self) -> str:
        return "DJANGO"

    def extract_trust_boundaries(
        self,
        parsed_file: ParsedFile,
        ast_tree: Optional[Any] = None,
        file_content: str = "",
    ) -> list[TrustBoundaryEvidence]:
        boundaries: list[TrustBoundaryEvidence] = []
        if parsed_file.language != "PYTHON":
            return boundaries

        tree = ast_tree
        if tree is None and file_content:
            try:
                tree = ast.parse(file_content)
            except Exception:
                return boundaries

        if tree is None:
            return boundaries

        for node in ast.walk(tree):
            # 1. Django View Function Entrypoints
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_django_view(node):
                    auth_state = self.extract_authentication_state(node, parsed_file.file_path)
                    authz_state, perm = self.extract_authorization_state(node, parsed_file.file_path)
                    # All parameters after 'request' are path/URL parameters
                    for idx, arg in enumerate(node.args.args):
                        if idx > 0 and arg.arg != "self":
                            boundaries.append(
                                TrustBoundaryEvidence(
                                    boundary_id=f"TB_DJANGO_PATH_{node.name}_{arg.arg}",
                                    boundary_type=TrustBoundaryType.HTTP_REQUEST_PARAM,
                                    framework="DJANGO",
                                    file_path=parsed_file.file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    symbol_name=arg.arg,
                                    is_authenticated=auth_state,
                                    is_authorized=authz_state,
                                    boundary_confidence="HIGH",
                                    details=f"Django URL path parameter '{arg.arg}' in view '{node.name}'",
                                )
                            )

            # 2. Django request attributes
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id in ("request", "req"):
                    attr = node.attr
                    b_type = (
                        TrustBoundaryType.HTTP_REQUEST_PARAM
                        if attr == "GET"
                        else TrustBoundaryType.HTTP_REQUEST_BODY
                        if attr in ("POST", "body")
                        else TrustBoundaryType.HTTP_COOKIE
                        if attr == "COOKIES"
                        else TrustBoundaryType.HTTP_REQUEST_HEADER
                        if attr in ("headers", "META")
                        else None
                    )
                    if b_type:
                        boundaries.append(
                            TrustBoundaryEvidence(
                                boundary_id=f"TB_DJANGO_{attr}_{node.lineno}",
                                boundary_type=b_type,
                                framework="DJANGO",
                                file_path=parsed_file.file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                symbol_name=f"request.{attr}",
                                is_authenticated=AuthenticationState.UNKNOWN,
                                is_authorized=AuthorizationState.UNKNOWN,
                                boundary_confidence="HIGH",
                                details=f"Django request data access request.{attr}",
                            )
                        )

        return boundaries

    def extract_authentication_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> AuthenticationState:
        if not hasattr(func_def, "decorator_list"):
            return AuthenticationState.UNKNOWN

        for dec in func_def.decorator_list:
            dec_name = self._get_decorator_name(dec)
            if dec_name == "login_required":
                return AuthenticationState.AUTHENTICATED

        return AuthenticationState.UNKNOWN

    def extract_authorization_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> tuple[AuthorizationState, Optional[str]]:
        if not hasattr(func_def, "decorator_list"):
            return (AuthorizationState.UNKNOWN, None)

        for dec in func_def.decorator_list:
            dec_name = self._get_decorator_name(dec)
            if dec_name == "permission_required":
                perm = self._get_decorator_first_arg(dec)
                return (AuthorizationState.PERMISSION_GRANTED, perm)
            elif dec_name == "user_passes_test":
                predicate = self._get_decorator_first_arg(dec)
                return (AuthorizationState.ROLE_VERIFIED, predicate)

        return (AuthorizationState.UNKNOWN, None)

    def _is_django_view(self, func_node: Any) -> bool:
        if not func_node.args or not func_node.args.args:
            return False
        first_arg = func_node.args.args[0].arg
        if first_arg == "request":
            return True
        if len(func_node.args.args) > 1 and first_arg == "self" and func_node.args.args[1].arg == "request":
            return True
        return False

    def _get_decorator_name(self, dec_node: Any) -> str:
        if isinstance(dec_node, ast.Name):
            return dec_node.id
        elif isinstance(dec_node, ast.Attribute):
            return dec_node.attr
        elif isinstance(dec_node, ast.Call):
            return self._get_decorator_name(dec_node.func)
        return ""

    def _get_decorator_first_arg(self, dec_node: Any) -> Optional[str]:
        if isinstance(dec_node, ast.Call) and dec_node.args:
            first = dec_node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
            elif isinstance(first, ast.Name):
                return first.id
        return None
