"""Custom exceptions for the CodeSentinel analyzer engine."""


class AnalyzerError(Exception):
    """Base exception for analyzer errors."""
    pass


class AnalysisCancelledError(AnalyzerError):
    """Raised when an in-progress analysis pipeline is cooperatively cancelled."""
    pass
