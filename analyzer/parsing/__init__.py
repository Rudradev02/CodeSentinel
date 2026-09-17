"""Language parsers generating normalized ParsedFile representations."""

from analyzer.parsing.base import BaseParser
from analyzer.parsing.javascript_parser import JavaScriptParser
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser

__all__ = [
    "BaseParser",
    "PythonParser",
    "JavaScriptParser",
    "TypeScriptParser",
]
