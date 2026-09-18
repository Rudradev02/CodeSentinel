"""JavaScript syntax tree parser using Tree-sitter.

Tree-sitter provides concrete syntax trees suitable for structured parsing
of JavaScript, JSX, and module imports/exports.
Phase 2 extracts syntactic structure, imports, exports, symbols, and source locations.
It does not claim complete semantic analysis or complete module resolution.
"""

from pathlib import Path
from typing import Optional

from tree_sitter import Language, Node, Parser
import tree_sitter_javascript

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


class JavaScriptParser(BaseParser):
    """Parses JavaScript and JSX source code into normalized ParsedFile structures."""

    def __init__(self):
        self.language = Language(tree_sitter_javascript.language())
        self.parser = Parser(self.language)

    def parse(self, file_path: Path, relative_path: str, content: str) -> ParsedFile:
        loc = len(content.splitlines())
        norm_rel = relative_path.replace("\\", "/")
        source_bytes = content.encode("utf-8", errors="replace")

        try:
            tree = self.parser.parse(source_bytes)
            root_node = tree.root_node

            imports: list[ImportStatement] = []
            exports: list[ExportStatement] = []
            symbols: list[SymbolDefinition] = []
            errors: list[ParseError] = []

            self._extract_declarations(root_node, source_bytes, imports, exports, symbols, errors)

            has_fatal_errors = any(err.error_type == "SYNTAX_ERROR" for err in errors)
            # If root node is entirely an error node
            if root_node.type == "ERROR":
                has_fatal_errors = True

            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="JAVASCRIPT",
                success=not has_fatal_errors,
                imports=imports,
                exports=exports,
                symbols=symbols,
                errors=errors,
                loc=loc,
            )
        except Exception as e:
            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="JAVASCRIPT",
                success=False,
                imports=[],
                exports=[],
                symbols=[],
                errors=[
                    ParseError(
                        message=f"Parser exception: {str(e)}",
                        line=None,
                        column=None,
                        error_type="PARSER_EXCEPTION",
                    )
                ],
                loc=loc,
            )

    def _extract_declarations(
        self,
        root: Node,
        source_bytes: bytes,
        imports: list[ImportStatement],
        exports: list[ExportStatement],
        symbols: list[SymbolDefinition],
        errors: list[ParseError],
    ) -> None:
        """Traverse concrete syntax tree to extract syntactic constructs."""
        cursor = root.walk()

        visited_nodes: list[Node] = []
        stack = [root]

        while stack:
            node = stack.pop()
            visited_nodes.append(node)

            # Check for syntax error nodes
            if node.type == "ERROR" or node.is_error:
                errors.append(
                    ParseError(
                        message="Syntax error encountered in JavaScript source tree",
                        line=node.start_point[0] + 1,
                        column=node.start_point[1],
                        error_type="SYNTAX_ERROR",
                    )
                )

            # 1. ES6 import_statement
            if node.type == "import_statement":
                self._handle_import_statement(node, source_bytes, imports)

            # 2. CommonJS require or dynamic import
            elif node.type == "call_expression":
                self._handle_call_expression(node, source_bytes, imports)

            # 3. export_statement
            elif node.type == "export_statement":
                self._handle_export_statement(node, source_bytes, exports, imports)

            # 4. Symbol definitions (functions, classes)
            elif node.type in ("function_declaration", "class_declaration", "generator_function_declaration"):
                self._handle_symbol_declaration(node, source_bytes, symbols)

            # Push children in reverse order for standard traversal
            for child in reversed(node.children):
                stack.append(child)

    def _handle_import_statement(
        self, node: Node, source_bytes: bytes, imports: list[ImportStatement]
    ) -> None:
        """Extract source module and symbols from an import_statement node."""
        source_module = None
        imported_names = []
        import_type = ImportType.STATIC

        for child in node.children:
            if child.type == "string":
                raw_str = source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                source_module = raw_str.strip("'\"`")
            elif child.type == "import_clause":
                clause_text = source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                if clause_text.startswith("type "):
                    import_type = ImportType.TYPE_ONLY
                self._extract_imported_names(child, source_bytes, imported_names)

        if source_module:
            imports.append(
                ImportStatement(
                    source_module=source_module,
                    imported_names=imported_names,
                    import_type=import_type,
                    line_number=node.start_point[0] + 1,
                    is_relative=source_module.startswith("."),
                    dependency_category=ImportCategory.UNRESOLVED,
                )
            )

    def _extract_imported_names(self, clause_node: Node, source_bytes: bytes, names: list[str]) -> None:
        """Collect identifier names from an import clause."""
        for child in clause_node.children:
            if child.type == "identifier":
                name = source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                names.append(name)
            elif child.type == "named_imports":
                for spec in child.children:
                    if spec.type == "import_specifier":
                        # Either simple identifier or alias 'name as alias'
                        id_nodes = [c for c in spec.children if c.type == "identifier"]
                        if id_nodes:
                            target_id = id_nodes[-1]
                            names.append(
                                source_bytes[target_id.start_byte : target_id.end_byte].decode("utf-8", errors="ignore")
                            )

    def _handle_call_expression(
        self, node: Node, source_bytes: bytes, imports: list[ImportStatement]
    ) -> None:
        """Detect CommonJS require('mod') and dynamic import('mod') calls."""
        if len(node.children) < 2:
            return

        callee = node.children[0]
        callee_text = source_bytes[callee.start_byte : callee.end_byte].decode("utf-8", errors="ignore")

        is_require = callee_text == "require"
        is_dynamic_import = callee_text == "import"

        if is_require or is_dynamic_import:
            # Look for string argument
            args_node = node.children[1] if len(node.children) > 1 else None
            if args_node and args_node.type == "arguments":
                for arg in args_node.children:
                    if arg.type == "string":
                        raw_str = source_bytes[arg.start_byte : arg.end_byte].decode("utf-8", errors="ignore")
                        clean_mod = raw_str.strip("'\"`")
                        imports.append(
                            ImportStatement(
                                source_module=clean_mod,
                                imported_names=[],
                                import_type=ImportType.DYNAMIC if is_dynamic_import else ImportType.STATIC,
                                line_number=node.start_point[0] + 1,
                                is_relative=clean_mod.startswith("."),
                                dependency_category=ImportCategory.UNRESOLVED,
                            )
                        )

    def _handle_export_statement(
        self, node: Node, source_bytes: bytes, exports: list[ExportStatement],
        imports: list[ImportStatement] = None,
    ) -> None:
        """Extract exported names from an export_statement node.
        
        Phase 6: Also extracts re-export source modules as ImportStatements
        (e.g., export { x } from './x' or export * from './module').
        """
        is_default = any(c.type == "default" for c in node.children)
        re_export_source = None

        for child in node.children:
            if child.type in ("function_declaration", "class_declaration"):
                for sub in child.children:
                    if sub.type == "identifier":
                        name = source_bytes[sub.start_byte : sub.end_byte].decode("utf-8", errors="ignore")
                        exports.append(
                            ExportStatement(
                                name=name,
                                is_default=is_default,
                                line_number=node.start_point[0] + 1,
                            )
                        )
                        break
                else:
                    if is_default:
                        exports.append(
                            ExportStatement(
                                name="default",
                                is_default=True,
                                line_number=node.start_point[0] + 1,
                            )
                        )
            elif child.type in ("lexical_declaration", "variable_declaration"):
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        for sub in decl.children:
                            if sub.type == "identifier":
                                name = source_bytes[sub.start_byte : sub.end_byte].decode("utf-8", errors="ignore")
                                exports.append(
                                    ExportStatement(
                                        name=name,
                                        is_default=is_default,
                                        line_number=node.start_point[0] + 1,
                                    )
                                )
                                break
            elif child.type == "export_clause":
                for spec in child.children:
                    if spec.type == "export_specifier":
                        id_nodes = [c for c in spec.children if c.type == "identifier"]
                        if id_nodes:
                            name = source_bytes[id_nodes[-1].start_byte : id_nodes[-1].end_byte].decode(
                                "utf-8", errors="ignore"
                            )
                            exports.append(
                                ExportStatement(
                                    name=name,
                                    is_default=False,
                                    line_number=node.start_point[0] + 1,
                                )
                            )
            elif child.type == "string":
                # Re-export source module: export { x } from './x' or export * from './module'
                raw_str = source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                re_export_source = raw_str.strip("'\"`")

        # Phase 6: Register re-export source as an import dependency
        if re_export_source and imports is not None:
            imports.append(
                ImportStatement(
                    source_module=re_export_source,
                    imported_names=[],
                    import_type=ImportType.STATIC,
                    line_number=node.start_point[0] + 1,
                    is_relative=re_export_source.startswith("."),
                    dependency_category=ImportCategory.UNRESOLVED,
                )
            )

    def _handle_symbol_declaration(
        self, node: Node, source_bytes: bytes, symbols: list[SymbolDefinition]
    ) -> None:
        """Record declared function and class symbols."""
        kind = SymbolKind.FUNCTION if "function" in node.type else SymbolKind.CLASS

        for child in node.children:
            if child.type in ("identifier", "type_identifier"):
                name = source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                symbols.append(
                    SymbolDefinition(
                        name=name,
                        kind=kind,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                )
                break
