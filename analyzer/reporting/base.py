from abc import ABC, abstractmethod
from typing import Optional
from analyzer.models.comparison import ComparisonResult
from analyzer.models.results import AnalysisResult


class BaseReporter(ABC):
    """Abstract interface for formatting analysis results."""

    @abstractmethod
    def render(self, result: AnalysisResult) -> str:
        """Render an AnalysisResult into a formatted string report."""
        pass

    def render_comparison(self, comparison: ComparisonResult) -> str:
        """Render a differential ComparisonResult into a formatted report."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support differential comparison rendering.")
