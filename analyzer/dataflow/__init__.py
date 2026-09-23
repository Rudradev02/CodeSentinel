"""Intraprocedural data-flow tracking and taint analysis package for CodeSentinel.

Strict Invariant:
Contains zero imports of backend, database, Celery, Redis, HTTP clients, or LLM providers.
"""

from analyzer.dataflow.symbol import (
    Definition,
    DefinitionKind,
    Reference,
    Scope,
    ScopeKind,
    SymbolTable,
)

__all__ = [
    "Definition",
    "DefinitionKind",
    "Reference",
    "Scope",
    "ScopeKind",
    "SymbolTable",
]
