"""Framework semantic adapters and boundary detection for CodeSentinel (Phase 23)."""

from analyzer.frameworks.base import BaseFrameworkAdapter, FrameworkModelRegistry
from analyzer.frameworks.django import DjangoAdapter
from analyzer.frameworks.express import ExpressAdapter
from analyzer.frameworks.flask import FlaskAdapter
from analyzer.frameworks.react import ReactAdapter

__all__ = [
    "BaseFrameworkAdapter",
    "FrameworkModelRegistry",
    "DjangoAdapter",
    "ExpressAdapter",
    "FlaskAdapter",
    "ReactAdapter",
]
