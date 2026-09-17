"""Tree-sitter helper functions for JavaScript and TypeScript security rules."""

from typing import Generator, Optional
from tree_sitter import Language, Node, Parser
import tree_sitter_javascript
import tree_sitter_typescript

_JS_LANGUAGE = Language(tree_sitter_javascript.language())
_TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
_TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())

_JS_PARSER = Parser(_JS_LANGUAGE)
_TS_PARSER = Parser(_TS_LANGUAGE)
_TSX_PARSER = Parser(_TSX_LANGUAGE)


def get_tree_sitter_parser_for_file(file_path: str) -> Parser:
    """Return the appropriate Tree-sitter parser based on file extension."""
    norm = file_path.lower()
    if norm.endswith(".tsx"):
        return _TSX_PARSER
    elif norm.endswith((".ts", ".mts", ".cts")):
        return _TS_PARSER
    return _JS_PARSER


def parse_js_ts_source(file_path: str, content: str) -> tuple[Node, bytes]:
    """Parse JavaScript or TypeScript source code into a Tree-sitter root node and source bytes."""
    parser = get_tree_sitter_parser_for_file(file_path)
    source_bytes = content.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    return tree.root_node, source_bytes


def node_text(node: Optional[Node], source_bytes: bytes) -> str:
    """Extract decoded UTF-8 string text from a Tree-sitter node."""
    if node is None:
        return ""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def traverse_nodes(root: Node) -> Generator[Node, None, None]:
    """Depth-first traversal generator yielding every node in the syntax tree."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        # Add children in reverse so traversal order is natural top-to-bottom
        for child in reversed(node.children):
            stack.append(child)


def get_node_line_and_col(node: Node) -> tuple[int, int, int, int]:
    """Return (line_start, line_end, col_start, col_end) with 1-indexed lines and 0-indexed cols."""
    line_start = node.start_point[0] + 1
    line_end = node.end_point[0] + 1
    col_start = node.start_point[1]
    col_end = node.end_point[1]
    return line_start, line_end, col_start, col_end
