"""Deterministic symbol and lexical scope models for intraprocedural data-flow analysis."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ScopeKind(str, Enum):
    """Classification of lexical scope."""
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    ASYNC_FUNCTION = "ASYNC_FUNCTION"
    BLOCK = "BLOCK"


class DefinitionKind(str, Enum):
    """Classification of how a symbol definition was created."""
    PARAMETER = "PARAMETER"
    ASSIGNMENT = "ASSIGNMENT"
    REASSIGNMENT = "REASSIGNMENT"
    IMPORT_BINDING = "IMPORT_BINDING"


class Definition(BaseModel):
    """Represents a symbol definition (assignment, parameter binding, etc.)."""
    symbol_name: str
    kind: DefinitionKind
    line: int
    col: int
    scope_id: str
    raw_expr: Optional[str] = None


class Reference(BaseModel):
    """Represents a reference/use of a symbol."""
    symbol_name: str
    line: int
    col: int
    scope_id: str
    is_write: bool = False
    resolving_definition: Optional[Definition] = None


class Scope(BaseModel):
    """Represents an isolated lexical scope with strictly deterministic identifier."""
    id: str = Field(..., description="Deterministic scope identifier")
    name: str = Field(..., description="Local identifier or function name")
    qualified_name: str = Field(..., description="Full lexical path (e.g. MyClass.process_data)")
    kind: ScopeKind
    line_start: int
    line_end: int
    col_start: int = 0
    parent_id: Optional[str] = None
    children_ids: list[str] = Field(default_factory=list)
    definitions: dict[str, list[Definition]] = Field(default_factory=dict)
    references: list[Reference] = Field(default_factory=list)

    @classmethod
    def create_deterministic_id(
        cls,
        rel_file_path: str,
        kind: ScopeKind,
        qualified_name: str,
        line_start: int,
        col_start: int = 0,
    ) -> str:
        """Construct a stable, deterministic scope ID without random UUIDs."""
        norm_path = rel_file_path.replace("\\", "/").strip("/")
        return f"{norm_path}::{kind.value}::{qualified_name}::{line_start}:{col_start}"

    def add_definition(
        self,
        symbol_name: str,
        kind: DefinitionKind,
        line: int,
        col: int,
        raw_expr: Optional[str] = None,
    ) -> Definition:
        """Register a new symbol definition in this scope."""
        if symbol_name in self.definitions and self.definitions[symbol_name]:
            if kind == DefinitionKind.ASSIGNMENT:
                kind = DefinitionKind.REASSIGNMENT

        defn = Definition(
            symbol_name=symbol_name,
            kind=kind,
            line=line,
            col=col,
            scope_id=self.id,
            raw_expr=raw_expr,
        )
        self.definitions.setdefault(symbol_name, []).append(defn)
        return defn

    def lookup_local_definition(
        self,
        symbol_name: str,
        line: Optional[int] = None,
    ) -> Optional[Definition]:
        """Find the latest local definition active at or before the given line number."""
        defs = self.definitions.get(symbol_name)
        if not defs:
            return None
        if line is None:
            return defs[-1]

        # Filter definitions active before or on this line, taking the latest
        candidates = [d for d in defs if d.line <= line]
        if candidates:
            return candidates[-1]
        return None


class SymbolTable(BaseModel):
    """Hierarchical symbol table managing scopes and cross-scope resolution."""
    scopes: dict[str, Scope] = Field(default_factory=dict)
    root_scope_id: Optional[str] = None

    def add_scope(self, scope: Scope) -> None:
        """Add a scope to the symbol table."""
        self.scopes[scope.id] = scope
        if scope.parent_id and scope.parent_id in self.scopes:
            parent = self.scopes[scope.parent_id]
            if scope.id not in parent.children_ids:
                parent.children_ids.append(scope.id)
        elif self.root_scope_id is None:
            self.root_scope_id = scope.id

    def get_scope(self, scope_id: str) -> Optional[Scope]:
        """Retrieve a scope by ID."""
        return self.scopes.get(scope_id)

    def resolve_symbol(
        self,
        symbol_name: str,
        from_scope_id: str,
        line: Optional[int] = None,
    ) -> Optional[Definition]:
        """Resolve a symbol reference starting from from_scope_id walking up parent scopes.
        
        Shadowing guarantee:
        Local scope definitions shadow definitions in enclosing outer scopes.
        """
        curr_id: Optional[str] = from_scope_id
        is_origin_scope = True

        while curr_id:
            scope = self.scopes.get(curr_id)
            if not scope:
                break

            # In the origin scope, respect line number. In enclosing scopes, any active def is visible.
            defn = scope.lookup_local_definition(
                symbol_name,
                line=line if is_origin_scope else None,
            )
            if defn:
                return defn

            is_origin_scope = False
            curr_id = scope.parent_id

        return None
