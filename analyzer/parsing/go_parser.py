"""Go syntax tree parser using Tree-sitter.

Extracts imports, symbols (functions, methods, types), and computes loc.
"""

from pathlib import Path
from typing import Optional

from tree_sitter import Language, Node, Parser
import tree_sitter_go

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
from analyzer.adapters.base import BaseLanguageAdapter, LanguageCapability


class GoParser(BaseLanguageAdapter):
    """Parses Go source code into normalized ParsedFile structures."""

    @property
    def language_id(self) -> str:
        return "GO"

    @property
    def capabilities(self) -> set[LanguageCapability]:
        return {LanguageCapability.AST_PARSING, LanguageCapability.CONTRACT_EXTRACTION}

    def __init__(self):
        self.language = Language(tree_sitter_go.language())
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
            if root_node.type == "ERROR":
                has_fatal_errors = True

            return ParsedFile(
                file_path=str(file_path.resolve()),
                relative_path=norm_rel,
                language="GO",
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
                language="GO",
                success=False,
                imports=[],
                exports=[],
                symbols=[],
                errors=[
                    ParseError(
                        message=f"Tree-sitter Go parsing failed: {str(e)}",
                        error_type="PARSER_EXCEPTION",
                    )
                ],
                loc=loc,
            )

    def _extract_declarations(
        self,
        node: Node,
        source: bytes,
        imports: list[ImportStatement],
        exports: list[ExportStatement],
        symbols: list[SymbolDefinition],
        errors: list[ParseError]
    ) -> None:
        if node.type == "ERROR":
            errors.append(
                ParseError(
                    message="Syntax error detected by tree-sitter",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    error_type="SYNTAX_ERROR"
                )
            )
            # Continue traversal to extract as much as possible

        if node.type == "import_declaration":
            self._handle_import(node, source, imports)
        elif node.type == "function_declaration":
            self._handle_function(node, source, symbols, exports)
        elif node.type == "method_declaration":
            self._handle_method(node, source, symbols, exports)
        elif node.type == "type_declaration":
            self._handle_type_declaration(node, source, symbols, exports)

        for child in node.children:
            self._extract_declarations(child, source, imports, exports, symbols, errors)

    def _handle_import(self, node: Node, source: bytes, imports: list[ImportStatement]) -> None:
        for child in node.children:
            if child.type == "import_spec_list":
                for spec in child.children:
                    if spec.type == "import_spec":
                        self._process_import_spec(spec, source, imports)
            elif child.type == "import_spec":
                self._process_import_spec(child, source, imports)

    def _process_import_spec(self, spec_node: Node, source: bytes, imports: list[ImportStatement]) -> None:
        path_node = spec_node.child_by_field_name("path")
        if not path_node:
            return
            
        path_str = source[path_node.start_byte:path_node.end_byte].decode("utf-8").strip('"')
        
        name_node = spec_node.child_by_field_name("name")
        imported_names = []
        if name_node:
            alias = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
            if alias != ".":
                imported_names = [alias]
                
        imports.append(
            ImportStatement(
                source_module=path_str,
                imported_names=imported_names,
                import_type=ImportType.STATIC,
                line_number=spec_node.start_point[0] + 1,
                is_relative=path_str.startswith("./") or path_str.startswith("../"),
                dependency_category=ImportCategory.UNRESOLVED,
            )
        )

    def _handle_function(self, node: Node, source: bytes, symbols: list[SymbolDefinition], exports: list[ExportStatement]) -> None:
        name_node = node.child_by_field_name("name")
        if name_node:
            name = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
            symbols.append(
                SymbolDefinition(
                    name=name,
                    kind=SymbolKind.FUNCTION,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                )
            )
            if name and name[0].isupper():
                exports.append(ExportStatement(name=name, is_default=False, line_number=node.start_point[0] + 1))

    def _handle_method(self, node: Node, source: bytes, symbols: list[SymbolDefinition], exports: list[ExportStatement]) -> None:
        name_node = node.child_by_field_name("name")
        receiver_node = node.child_by_field_name("receiver")
        
        if name_node and receiver_node:
            name = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
            
            # Try to extract the receiver type to build a fully qualified method name (e.g. Server.Handle)
            receiver_type = ""
            for child in receiver_node.children:
                if child.type == "parameter_declaration":
                    type_node = child.child_by_field_name("type")
                    if type_node:
                        # Handle pointer receivers
                        if type_node.type == "pointer_type":
                            base_type = type_node.children[1] if len(type_node.children) > 1 else None
                            if base_type:
                                receiver_type = source[base_type.start_byte:base_type.end_byte].decode("utf-8")
                        else:
                            receiver_type = source[type_node.start_byte:type_node.end_byte].decode("utf-8")
                    break
            
            full_name = f"{receiver_type}.{name}" if receiver_type else name
            
            symbols.append(
                SymbolDefinition(
                    name=full_name,
                    kind=SymbolKind.FUNCTION,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                )
            )
            if name and name[0].isupper():
                exports.append(ExportStatement(name=full_name, is_default=False, line_number=node.start_point[0] + 1))

    def _handle_type_declaration(self, node: Node, source: bytes, symbols: list[SymbolDefinition], exports: list[ExportStatement]) -> None:
        for child in node.children:
            if child.type == "type_spec":
                name_node = child.child_by_field_name("name")
                type_node = child.child_by_field_name("type")
                if name_node and type_node:
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
                    kind = SymbolKind.CLASS
                    if type_node.type == "interface_type":
                        kind = SymbolKind.INTERFACE
                        
                    symbols.append(
                        SymbolDefinition(
                            name=name,
                            kind=kind,
                            line_start=child.start_point[0] + 1,
                            line_end=child.end_point[0] + 1,
                        )
                    )
                    if name and name[0].isupper():
                        exports.append(ExportStatement(name=name, is_default=False, line_number=child.start_point[0] + 1))
