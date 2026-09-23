"""Bounded AST Context Extraction service for Phase 12 AI Enrichment.

Extracts narrow, relevant surrounding code scope (enclosing function, class, or
line window) and referenced imports while enforcing a strict 2,048-token budget.
"""

import ast
from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

# Heuristic token approximation: ~4 characters per token
MAX_TOKEN_BUDGET = 2048
MAX_CHAR_BUDGET = MAX_TOKEN_BUDGET * 4  # ~8,192 chars total (including prompts)
MAX_CONTEXT_CHARS = 5500  # Context payload limit to leave buffer for prompts & JSON schema


@dataclass
class BoundedContext:
    """Bounded source code context surrounding a candidate finding."""

    file_path: str
    line_start: int
    line_end: int
    enclosing_symbol_name: Optional[str] = None
    enclosing_symbol_kind: str = "WINDOW"  # "FUNCTION", "CLASS", or "WINDOW"
    enclosing_source: str = ""
    relevant_imports: List[str] = field(default_factory=list)
    estimated_tokens: int = 0
    was_truncated: bool = False


class ContextBuilder:
    """Constructs bounded, sanitized AST context envelopes for candidate findings."""

    @classmethod
    def extract_context(
        f_cls,
        repo_root: Path,
        file_path: str,
        line_start: int,
        line_end: Optional[int] = None,
        language: str = "plaintext",
    ) -> BoundedContext:
        """Extract bounded context surrounding a finding from the repository source."""
        target_file = (repo_root / file_path).resolve()
        end_line = line_end or line_start

        # Security check: verify resolved path is inside repo_root
        try:
            target_file.relative_to(repo_root.resolve())
        except ValueError:
            logger.warning("Attempted path traversal in context builder: %s", file_path)
            return BoundedContext(
                file_path=file_path,
                line_start=line_start,
                line_end=end_line,
                enclosing_source="// [Access denied: file outside repository boundary]",
            )

        if not target_file.exists() or not target_file.is_file():
            return BoundedContext(
                file_path=file_path,
                line_start=line_start,
                line_end=end_line,
                enclosing_source="// [File not found on disk]",
            )

        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Could not read file %s for context extraction: %s", file_path, exc)
            return BoundedContext(
                file_path=file_path,
                line_start=line_start,
                line_end=end_line,
                enclosing_source=f"// [Error reading file: {exc}]",
            )

        lines = content.splitlines()
        lang_lower = language.lower()

        if lang_lower == "python" or file_path.endswith(".py"):
            return f_cls._extract_python_context(lines, file_path, line_start, end_line)
        elif lang_lower in ("javascript", "typescript") or file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
            return f_cls._extract_js_ts_context(lines, file_path, line_start, end_line)
        else:
            return f_cls._extract_window_context(lines, file_path, line_start, end_line)

    @classmethod
    def _extract_python_context(
        cls,
        lines: List[str],
        file_path: str,
        line_start: int,
        line_end: int,
    ) -> BoundedContext:
        """Extract Python AST enclosing function/class and relevant imports."""
        source_code = "\n".join(lines)
        enclosing_node: Optional[ast.AST] = None
        all_imports: List[str] = []

        try:
            tree = ast.parse(source_code)
            all_imports = cls._collect_python_imports(tree, lines)

            # Find narrowest enclosing function or class
            candidates = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = getattr(node, "lineno", 0)
                    end = getattr(node, "end_lineno", start)
                    if start <= line_start and end >= line_end:
                        candidates.append((end - start, node))

            if candidates:
                # Pick smallest span
                candidates.sort(key=lambda c: c[0])
                enclosing_node = candidates[0][1]

        except Exception as parse_exc:
            logger.debug("Python AST parse failed in context builder for %s: %s", file_path, parse_exc)

        if enclosing_node is not None:
            sym_name = getattr(enclosing_node, "name", "unknown")
            sym_kind = "CLASS" if isinstance(enclosing_node, ast.ClassDef) else "FUNCTION"
            start_l = getattr(enclosing_node, "lineno", line_start)
            end_l = getattr(enclosing_node, "end_lineno", line_end)

            symbol_lines = lines[start_l - 1 : end_l]
            symbol_text = "\n".join(symbol_lines)

            # Filter imports referenced in this symbol
            relevant_imports = [imp for imp in all_imports if any(word in symbol_text for word in imp.split())]

            context = BoundedContext(
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                enclosing_symbol_name=sym_name,
                enclosing_symbol_kind=sym_kind,
                enclosing_source=symbol_text,
                relevant_imports=relevant_imports[:15],
            )
        else:
            context = cls._extract_window_context(lines, file_path, line_start, line_end)
            context.relevant_imports = all_imports[:10]

        return cls._enforce_budget(context)

    @classmethod
    def _collect_python_imports(cls, tree: ast.AST, lines: List[str]) -> List[str]:
        """Collect top-level import statements from Python AST."""
        imports = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                lineno = getattr(node, "lineno", None)
                if lineno and 1 <= lineno <= len(lines):
                    imports.append(lines[lineno - 1].strip())
        return imports

    @classmethod
    def _extract_js_ts_context(
        cls,
        lines: List[str],
        file_path: str,
        line_start: int,
        line_end: int,
    ) -> BoundedContext:
        """Extract JavaScript/TypeScript surrounding scope and imports."""
        all_imports = []
        import_pattern = re.compile(r"^\s*(import\s+.+from\s+[\'\"]|const\s+.+=\s*require\([\'\"])")

        for line in lines[:80]:  # Scan top 80 lines for imports
            if import_pattern.match(line):
                all_imports.append(line.strip())

        # Scan backwards from line_start to identify enclosing function/class header
        header_pattern = re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([A-Za-z0-9_$]+)|class\s+([A-Za-z0-9_$]+)|(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)"
        )
        sym_name = None
        sym_kind = "WINDOW"
        sym_start = max(1, line_start - 25)

        for i in range(line_start - 1, max(-1, line_start - 60), -1):
            if i < len(lines):
                match = header_pattern.match(lines[i])
                if match:
                    sym_name = match.group(1) or match.group(2) or match.group(3)
                    sym_kind = "CLASS" if "class" in lines[i] else "FUNCTION"
                    sym_start = i + 1
                    break

        sym_end = min(len(lines), line_end + 30)
        symbol_lines = lines[sym_start - 1 : sym_end]
        symbol_text = "\n".join(symbol_lines)

        relevant_imports = [imp for imp in all_imports if any(word in symbol_text for word in imp.split())]

        context = BoundedContext(
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            enclosing_symbol_name=sym_name,
            enclosing_symbol_kind=sym_kind,
            enclosing_source=symbol_text,
            relevant_imports=relevant_imports[:15],
        )

        return cls._enforce_budget(context)

    @classmethod
    def _extract_window_context(
        cls,
        lines: List[str],
        file_path: str,
        line_start: int,
        line_end: int,
    ) -> BoundedContext:
        """Fallback line window context: 15 lines before and after finding."""
        start = max(1, line_start - 15)
        end = min(len(lines), line_end + 15)
        window_lines = lines[start - 1 : end]

        context = BoundedContext(
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            enclosing_symbol_name=None,
            enclosing_symbol_kind="WINDOW",
            enclosing_source="\n".join(window_lines),
            relevant_imports=[],
        )
        return cls._enforce_budget(context)

    @classmethod
    def _enforce_budget(cls, context: BoundedContext) -> BoundedContext:
        """Enforce strict character budget (~MAX_CONTEXT_CHARS) with priority truncation."""
        total_chars = len(context.enclosing_source) + sum(len(imp) for imp in context.relevant_imports)

        if total_chars > MAX_CONTEXT_CHARS:
            context.was_truncated = True

            # Step 1: Drop imports if budget exceeded
            if len(context.enclosing_source) > MAX_CONTEXT_CHARS:
                context.relevant_imports = []
            else:
                while context.relevant_imports and (len(context.enclosing_source) + sum(len(i) for i in context.relevant_imports)) > MAX_CONTEXT_CHARS:
                    context.relevant_imports.pop()

            # Step 2: Truncate source if still over budget (keep head & tail around finding)
            if len(context.enclosing_source) > MAX_CONTEXT_CHARS:
                lines = context.enclosing_source.splitlines()
                if len(lines) > 40:
                    head = lines[:25]
                    tail = lines[-15:]
                    truncated_lines = head + ["    # ... [code omitted for token budget] ..."] + tail
                    context.enclosing_source = "\n".join(truncated_lines)
                else:
                    context.enclosing_source = context.enclosing_source[:MAX_CONTEXT_CHARS] + "\n// ... [truncated]"

        context.estimated_tokens = (len(context.enclosing_source) + sum(len(i) for i in context.relevant_imports)) // 4
        return context
