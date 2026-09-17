"""Dependency analysis and import resolution."""

from analyzer.dependencies.imports import is_node_builtin, is_python_stdlib
from analyzer.dependencies.resolver import DependencyResolver

__all__ = ["is_python_stdlib", "is_node_builtin", "DependencyResolver"]
