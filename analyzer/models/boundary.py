"""Trust boundary and entrypoint models for CodeSentinel (Phase 23).

Defines strongly-typed representations of trust boundaries where external,
potentially untrusted data enters the application across framework boundaries.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict


class TrustBoundaryType(str, Enum):
    """Classification of the trust boundary origin."""
    HTTP_REQUEST_PARAM = "HTTP_REQUEST_PARAM"      # URL query parameters (?key=val)
    HTTP_REQUEST_BODY = "HTTP_REQUEST_BODY"        # Request body (JSON, form-encoded)
    HTTP_REQUEST_HEADER = "HTTP_REQUEST_HEADER"    # Request headers
    HTTP_COOKIE = "HTTP_COOKIE"                    # Cookie values
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"  # os.environ
    CLI_ARGUMENT = "CLI_ARGUMENT"                  # sys.argv, argparse
    DOM_INPUT = "DOM_INPUT"                        # location.search, input.value
    EXTERNAL_API = "EXTERNAL_API"                  # Third-party HTTP response payload
    INTERNAL_SERVICE = "INTERNAL_SERVICE"          # Trusted internal RPC/call


class AuthenticationState(str, Enum):
    """Discrete evidence-based authentication state."""
    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN = "UNKNOWN"


class AuthorizationState(str, Enum):
    """Discrete evidence-based authorization state."""
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    ROLE_VERIFIED = "ROLE_VERIFIED"
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    UNKNOWN = "UNKNOWN"


class TrustBoundaryEvidence(BaseModel):
    """Evidence capturing a specific trust boundary crossing."""
    model_config = ConfigDict(frozen=True)

    boundary_id: str
    boundary_type: TrustBoundaryType
    framework: str = "GENERAL"  # "FLASK", "DJANGO", "REACT", "EXPRESS", "GENERAL"
    file_path: str
    line: int
    column: int = 0
    symbol_name: str            # e.g. "request.args['id']"
    route_pattern: Optional[str] = None
    http_method: Optional[str] = None
    is_authenticated: AuthenticationState = AuthenticationState.UNKNOWN
    is_authorized: AuthorizationState = AuthorizationState.UNKNOWN
    boundary_confidence: str = "HIGH"  # "HIGH", "MEDIUM", "LOW"
    details: str = ""
