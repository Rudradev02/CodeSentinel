"""Abstract base reporter contract for CodeSentinel."""

from abc import ABC, abstractmethod

from analyzer.models.results import AnalysisResult


class BaseReporter(ABC):
    """Abstract interface for formatting analysis results."""

    @abstractmethod
    def render(self, result: AnalysisResult) -> str:
        """Render an AnalysisResult into a formatted string report."""
        pass
