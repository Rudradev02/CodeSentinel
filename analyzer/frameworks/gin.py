"""Gin and net/http framework intelligence adapter."""

from typing import Any, Optional

from analyzer.frameworks.base import BaseFrameworkAdapter, FrameworkCapability
from analyzer.models.boundary import (
    AuthenticationState,
    AuthorizationState,
    TrustBoundaryEvidence,
    TrustBoundaryType,
)
from analyzer.models.parse import ParsedFile


class GinAdapter(BaseFrameworkAdapter):
    """Adapter for extracting routes, auth, and trust boundaries from Go Gin and net/http applications."""

    @property
    def framework_name(self) -> str:
        return "GIN"

    @property
    def capability(self) -> FrameworkCapability:
        return FrameworkCapability(
            framework_id="GIN",
            display_name="Gin",
            supports_route_extraction=True,
            supports_path_parameters=True,
            supports_request_body=True,
            supports_authentication_extraction=True,
            supports_authorization_extraction=True,
            supported_versions=">=1.0.0",
            detection_manifest_tokens=["github.com/gin-gonic/gin", "net/http"],
            detection_source_tokens=["gin.Context", "http.Request"],
        )

    def extract_trust_boundaries(
        self,
        parsed_file: ParsedFile,
        ast_tree: Optional[Any] = None,
        file_content: str = "",
    ) -> list[TrustBoundaryEvidence]:
        """Extract HTTP routes and controller handlers as trust boundaries."""
        boundaries: list[TrustBoundaryEvidence] = []
        if not ast_tree or not file_content:
            return boundaries
            
        source = file_content.encode("utf-8", errors="replace")
        
        def walk(node: Any):
            if getattr(node, "type", None) == "call_expression":
                # Detect r.GET, r.POST, http.HandleFunc etc
                func_node = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
                if func_node and getattr(func_node, "type", None) == "selector_expression":
                    field_node = func_node.child_by_field_name("field")
                    if field_node:
                        method_name = source[field_node.start_byte:field_node.end_byte].decode("utf-8")
                        if method_name in ("GET", "POST", "PUT", "DELETE", "PATCH", "HandleFunc"):
                            args_node = node.child_by_field_name("arguments")
                            if args_node and len(args_node.children) >= 3:
                                path_node = args_node.children[1]
                                path_str = source[path_node.start_byte:path_node.end_byte].decode("utf-8").strip('"')
                                boundaries.append(
                                    TrustBoundaryEvidence(
                                        boundary_type=TrustBoundaryType.HTTP_ROUTE,
                                        identifier=f"{method_name} {path_str}",
                                        line_number=node.start_point[0] + 1,
                                        is_authenticated=AuthenticationState.UNKNOWN_AUTHENTICATION,
                                        required_permission=None,
                                    )
                                )
            
            if hasattr(node, "children"):
                for child in node.children:
                    walk(child)
                
        if hasattr(ast_tree, "root_node"):
            walk(ast_tree.root_node)
            
        return boundaries

    def extract_authentication_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> AuthenticationState:
        """Gin relies on middleware (e.g. authMiddleware()) which must be checked in the route registration."""
        return AuthenticationState.UNKNOWN_AUTHENTICATION

    def extract_authorization_state(
        self,
        func_def: Any,
        file_path: str,
    ) -> tuple[AuthorizationState, Optional[str]]:
        return AuthorizationState.UNKNOWN_AUTHORIZATION, None
