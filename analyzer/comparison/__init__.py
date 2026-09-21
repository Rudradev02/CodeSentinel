"""Differential baseline comparison package for CodeSentinel."""

from analyzer.comparison.diff import BaselineComparator
from analyzer.models.comparison import (
    ComparisonResult,
    ComparisonSummary,
    ComponentGraphDelta,
    DifferentialFinding,
    FindingTransition,
    HealthDelta,
)

__all__ = [
    "BaselineComparator",
    "ComparisonResult",
    "ComparisonSummary",
    "ComponentGraphDelta",
    "DifferentialFinding",
    "FindingTransition",
    "HealthDelta",
]
