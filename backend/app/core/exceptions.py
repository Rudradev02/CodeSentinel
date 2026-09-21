"""Custom domain and API exceptions for CodeSentinel."""

from typing import Any, Optional


class CodeSentinelAPIException(Exception):
    """Base exception for all structured CodeSentinel API errors."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


class PathNotFoundException(CodeSentinelAPIException):
    """Raised when target repository path does not exist on disk (HTTP 404)."""

    def __init__(self, path: str):
        super().__init__(
            status_code=404,
            code="NOT_FOUND",
            message=f"Repository path does not exist: '{path}'",
            details={"path": path},
        )


class InvalidPathException(CodeSentinelAPIException):
    """Raised when target path is a file or not a directory (HTTP 400)."""

    def __init__(self, path: str, reason: str = "Path must be a directory"):
        super().__init__(
            status_code=400,
            code="INVALID_PATH",
            message=f"Invalid repository path: {reason}",
            details={"path": path, "reason": reason},
        )


class SecurityPolicyViolationException(CodeSentinelAPIException):
    """Raised when repository path violates security boundary (HTTP 403)."""

    def __init__(self, path: str, reason: str):
        super().__init__(
            status_code=403,
            code="SECURITY_POLICY_VIOLATION",
            message=f"Security boundary policy violation: {reason}",
            details={"path": path, "reason": reason},
        )


class RuleNotFoundException(CodeSentinelAPIException):
    """Raised when requested rule ID is not registered (HTTP 404)."""

    def __init__(self, rule_id: str):
        super().__init__(
            status_code=404,
            code="RULE_NOT_FOUND",
            message=f"Static analysis rule not found: '{rule_id}'",
            details={"rule_id": rule_id},
        )
