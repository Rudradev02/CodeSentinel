"""Rule engine and registry exports for CodeSentinel."""

from typing import Any

__all__ = [
    "RuleEngine",
    "RuleRegistry",
]


def __getattr__(name: str) -> Any:
    if name == "RuleEngine":
        from analyzer.rules.engine import RuleEngine
        return RuleEngine
    if name == "RuleRegistry":
        from analyzer.rules.registry import RuleRegistry
        return RuleRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
