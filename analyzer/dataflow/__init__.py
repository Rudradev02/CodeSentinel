"""Intraprocedural data-flow tracking and taint analysis package for CodeSentinel.

Strict Invariant:
Pure static analyzer with zero imports of external web servers, task queues, or persistence drivers.
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
