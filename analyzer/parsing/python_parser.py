"""Python AST parser using the native Python standard library ast module."""

import ast
from pathlib import Path

from analyzer.models.graph import ImportType
from analyzer.models.parse import (
    ExportStatement,
    ImportCategory,
    ImportStatement,
    ParsedFile,
    ParseError,
    SymbolDefinition,
    SymbolKind,
)
from analyzer.parsing.base import BaseParser


class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor extracting imports, function/class declarations, and exports."""

    def __init__(self):
        self.imports: list[ImportStatement] = []
        self.symbols: list[SymbolDefinition] = []
        self.exports: list[ExportStatement] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                ImportStatement(
                    source_module=alias.name,
                    imported_names=[alias.asname or alias.name],
                    import_type=ImportType.STATIC,
                    line_number=node.lineno,
                    is_relative=False,
                    dependency_category=ImportCategory.UNRESOLVED,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        is_rel = (node.level or 0) > 0
        dots = "." * (node.level or 0) if is_rel else ""
        base_mod = node.module or ""
        full_module = f"{dots}{base_mod}"

        names = [alias.name for alias in node.names]
        self.imports.append(
            ImportStatement(
                source_module=full_module,
                imported_names=names,
                import_type=ImportType.STATIC,
                line_number=node.lineno,
                is_relative=is_rel,
                dependency_category=ImportCategory.UNRESOLVED,
            )
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Detect dynamic imports: __import__('name') or importlib.import_module('name')
        is_dynamic = False
        target_mod = None

        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            is_dynamic = True
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                target_mod = node.args[0].value

        elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
            is_dynamic = True
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                target_mod = node.args[0].value

        if is_dynamic and target_mod:
            self.imports.append(
                ImportStatement(
                    source_module=target_mod,
                    imported_names=[],
                    import_type=ImportType.DYNAMIC,
                    line_number=node.lineno,
                    is_relative=target_mod.startswith("."),
                    dependency_category=ImportCategory.UNRESOLVED,
                )
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.symbols.append(
            SymbolDefinition(
                name=node.name,
                kind=SymbolKind.FUNCTION,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno) or node.lineno,
            )
        )
        if not node.name.startswith("_"):
            self.exports.append(
                ExportStatement(
                    name=node.name,
                    is_default=False,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.symbols.append(
            SymbolDefinition(
                name=node.name,
                kind=SymbolKind.FUNCTION,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno) or node.lineno,
            )
        )
        if not node.name.startswith("_"):
            self.exports.append(
                ExportStatement(
                    name=node.name,
                    is_default=False,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.symbols.append(
            SymbolDefinition(
                name=node.name,
                kind=SymbolKind.CLASS,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno) or node.lineno,
            )
        )
        if not node.name.startswith("_"):
            self.exports.append(
                ExportStatement(
                    name=node.name,
                    is_default=False,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)


class PythonParser(BaseParser):
    """Parses Python source code into a normalized ParsedFile representation."""

    def parse(self, file_path: Path, relative_path: str, content: str) -> ParsedFile:
        loc = len(content.splitlines())
        norm_rel = relative_path.replace("\\", "/")

        try:
            tree = ast.parse(content, filename=str(file_path))
            visitor = PythonASTVisitor()
            visitor.visit(tree)

            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="PYTHON",
                success=True,
                imports=visitor.imports,
                exports=visitor.exports,
                symbols=visitor.symbols,
                errors=[],
                loc=loc,
            )
        except (SyntaxError, IndentationError) as e:
            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="PYTHON",
                success=False,
                imports=[],
                exports=[],
                symbols=[],
                errors=[
                    ParseError(
                        message=f"{type(e).__name__}: {e.msg if hasattr(e, 'msg') else str(e)}",
                        line=getattr(e, "lineno", None),
                        column=getattr(e, "offset", None),
                        error_type="SYNTAX_ERROR",
                    )
                ],
                loc=loc,
            )
        except Exception as e:
            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="PYTHON",
                success=False,
                imports=[],
                exports=[],
                symbols=[],
                errors=[
                    ParseError(
                        message=f"Unexpected parsing failure: {str(e)}",
                        line=None,
                        column=None,
                        error_type="PARSER_EXCEPTION",
                    )
                ],
                loc=loc,
            )
