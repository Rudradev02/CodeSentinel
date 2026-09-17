"""Normalized parse representation and symbol extraction models for CodeSentinel."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from analyzer.models.graph import ImportType


class ImportCategory(str, Enum):
    """Classification of resolved import dependency."""
    LOCAL = "LOCAL"            # Resolves to a module within the audited repository
    STDLIB = "STDLIB"          # Belongs to Python/runtime standard library
    EXTERNAL = "EXTERNAL"      # Third-party package/dependency (e.g. from npm/PyPI)
    UNRESOLVED = "UNRESOLVED"  # Local/relative import that failed resolution


class ImportStatement(BaseModel):
    """Normalized representation of an import statement across all supported languages."""
    source_module: str = Field(..., description="Raw imported module identifier or path")
    imported_names: list[str] = Field(default_factory=list, description="Specific imported symbols/names")
    import_type: ImportType = Field(default=ImportType.STATIC)
    line_number: Optional[int] = Field(default=None, ge=1)
    is_relative: bool = Field(default=False, description="True if import starts with relative notation (./, ../)")
    resolved_path: Optional[str] = Field(default=None, description="Repository-relative path if resolved locally")
    dependency_category: ImportCategory = Field(default=ImportCategory.UNRESOLVED)


class ExportStatement(BaseModel):
    """Normalized representation of an export statement."""
    name: str = Field(..., description="Exported identifier name or default")
    is_default: bool = Field(default=False)
    line_number: Optional[int] = Field(default=None, ge=1)


class SymbolKind(str, Enum):
    """Classification of declared programming symbol."""
    FUNCTION = "FUNCTION"
    CLASS = "CLASS"
    VARIABLE = "VARIABLE"
    INTERFACE = "INTERFACE"
    TYPE_ALIAS = "TYPE_ALIAS"


class SymbolDefinition(BaseModel):
    """Information on declared functions, classes, and types."""
    name: str = Field(..., description="Symbol identifier name")
    kind: SymbolKind
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)


class ParseError(BaseModel):
    """Detailed error encountered during source parsing."""
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    error_type: str = Field(default="SYNTAX_ERROR")


class ParsedFile(BaseModel):
    """Uniform normalized representation emitted by all language parsers."""
    file_path: str = Field(..., description="Absolute path on disk")
    relative_path: str = Field(..., description="Repository-relative path")
    language: str = Field(..., description="Detected language (PYTHON, JAVASCRIPT, TYPESCRIPT)")
    success: bool = Field(default=True, description="True if parsed without fatal syntax errors")
    imports: list[ImportStatement] = Field(default_factory=list)
    exports: list[ExportStatement] = Field(default_factory=list)
    symbols: list[SymbolDefinition] = Field(default_factory=list)
    errors: list[ParseError] = Field(default_factory=list)
    loc: int = Field(default=0, ge=0, description="Total physical lines of code")
