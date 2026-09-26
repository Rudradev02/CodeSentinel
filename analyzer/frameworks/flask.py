"""Flask framework semantic adapter for CodeSentinel (Phase 23)."""

from __future__ import annotations

import ast
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


class FlaskAdapter(BaseFrameworkAdapter):
    """Semantic adapter for Flask web applications."""

    @property
    def framework_name(self) -> str:
        return "FLASK"

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

        # Scan for Flask route definitions and request accesses
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route_info = self._get_route_info(node)
                if route_info:
                    route_pattern, methods = route_info
                    auth_state = self.extract_authentication_state(node, parsed_file.file_path)
                    authz_state, _ = self.extract_authorization_state(node, parsed_file.file_path)

                    # Extract path parameters from route pattern (e.g. "/user/<id>")
                    path_params = re.findall(r"<(?:\w+:)?(\w+)>", route_pattern)
                    for p in path_params:
                        boundaries.append(
                            TrustBoundaryEvidence(
                                boundary_id=f"TB_FLASK_PATH_{node.name}_{p}",
                                boundary_type=TrustBoundaryType.HTTP_REQUEST_PARAM,
                                framework="FLASK",
                                file_path=parsed_file.file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                symbol_name=p,
                                route_pattern=route_pattern,
                                http_method=",".join(methods) if methods else "GET",
                                is_authenticated=auth_state,
                                is_authorized=authz_state,
                                boundary_confidence="HIGH",
                                details=f"Flask path parameter '{p}' in route '{route_pattern}'",
                            )
                        )

            elif isinstance(node, ast.Attribute):
                # Check for request.args, request.form, request.values, request.json
                if isinstance(node.value, ast.Name) and node.value.id == "request":
                    attr = node.attr
                    b_type = (
                        TrustBoundaryType.HTTP_REQUEST_PARAM
                        if attr in ("args", "values")
                        else TrustBoundaryType.HTTP_REQUEST_BODY
                        if attr in ("form", "json", "data")
                        else TrustBoundaryType.HTTP_REQUEST_HEADER
                        if attr == "headers"
                        else TrustBoundaryType.HTTP_COOKIE
                        if attr == "cookies"
                        else None
                    )
                    if b_type:
                        boundaries.append(
                            TrustBoundaryEvidence(
                                boundary_id=f"TB_FLASK_REQ_{attr.upper()}_{node.lineno}",
                                boundary_type=b_type,
                                framework="FLASK",
                                file_path=parsed_file.file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                symbol_name=f"request.{attr}",
                                is_authenticated=AuthenticationState.UNKNOWN,
                                is_authorized=AuthorizationState.UNKNOWN,
                                boundary_confidence="HIGH",
                                details=f"Flask request attribute request.{attr}",
                            )
                        )

            elif isinstance(node, ast.Call):
                # Check for request.get_json(...)
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "request":
                        if node.func.attr == "get_json":
                            boundaries.append(
                                TrustBoundaryEvidence(
                                    boundary_id=f"TB_FLASK_GET_JSON_{node.lineno}",
                                    boundary_type=TrustBoundaryType.HTTP_REQUEST_BODY,
                                    framework="FLASK",
                                    file_path=parsed_file.file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    symbol_name="request.get_json()",
                                    is_authenticated=AuthenticationState.UNKNOWN,
                                    is_authorized=AuthorizationState.UNKNOWN,
                                    boundary_confidence="HIGH",
                                    details="Flask request body parsed via request.get_json()",
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
            if dec_name in ("login_required", "jwt_required", "fresh_jwt_required"):
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
            if dec_name in ("roles_required", "roles_accepted"):
                perm = self._get_decorator_first_arg(dec)
                return (AuthorizationState.ROLE_VERIFIED, perm)
            elif dec_name in ("permission_required",):
                perm = self._get_decorator_first_arg(dec)
                return (AuthorizationState.PERMISSION_GRANTED, perm)

        return (AuthorizationState.UNKNOWN, None)

    def _get_route_info(self, func_node: Any) -> Optional[tuple[str, list[str]]]:
        for dec in getattr(func_node, "decorator_list", []):
            if isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Attribute) and func.attr == "route":
                    pattern = "/"
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        pattern = dec.args[0].value
                    methods = ["GET"]
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            methods = [
                                elt.value
                                for elt in kw.value.elts
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                            ]
                    return (pattern, methods)
        return None

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
        return None
