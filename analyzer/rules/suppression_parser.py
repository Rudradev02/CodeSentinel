"""Inline suppression annotation parser for CodeSentinel (Phase 25).

Scans source file comments for ``codesentinel-suppress`` directives and
produces structured ``FindingSuppression`` records.

Supported syntax:
    # codesentinel-suppress SEC-PY-005
    # codesentinel-suppress SEC-PY-005 reason="Parameterized in ORM layer"
    # codesentinel-suppress SEC-PY-005 until=2025-12-31
    // codesentinel-suppress SEC-JS-003 reason="Sanitized by DOMPurify"
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from analyzer.models.suppression import (
    FindingSuppression,
    SuppressionKind,
    SuppressionScope,
)

# Matches: codesentinel-suppress RULE-ID [reason="..."] [until=YYYY-MM-DD]
_SUPPRESS_PATTERN = re.compile(
    r"codesentinel-suppress\s+"
    r"(?P<rule_id>[A-Z][\w-]+(?:\s*,\s*[A-Z][\w-]+)*)"  # One or more rule IDs
    r"(?:\s+reason=\"(?P<reason>[^\"]*)\")?"
    r"(?:\s+until=(?P<until>\d{4}-\d{2}-\d{2}))?"
)


def parse_inline_suppressions(
    source_content: str,
    file_path: str,
    language: str = "PYTHON",
) -> list[FindingSuppression]:
    """Parse inline suppression annotations from source file content.

    Scans all lines for comment-based ``codesentinel-suppress`` directives.

    Args:
        source_content: The full text content of the source file.
        file_path: Repository-relative file path for the source.
        language: Source language (``PYTHON``, ``JAVASCRIPT``, ``TYPESCRIPT``).

    Returns:
        List of FindingSuppression records extracted from the source.
    """
    suppressions: list[FindingSuppression] = []
    comment_prefixes = _comment_prefixes_for_language(language)

    for line_num, line in enumerate(source_content.splitlines(), start=1):
        stripped = line.strip()

        # Check if line contains a recognized comment
        comment_text: Optional[str] = None
        for prefix in comment_prefixes:
            idx = stripped.find(prefix)
            if idx >= 0:
                comment_text = stripped[idx + len(prefix):]
                break

        if comment_text is None:
            continue

        match = _SUPPRESS_PATTERN.search(comment_text)
        if not match:
            continue

        raw_rule_ids = match.group("rule_id")
        reason = match.group("reason") or ""
        until_str = match.group("until")

        # Parse expiration date
        expires_at: Optional[datetime] = None
        kind = SuppressionKind.INLINE_ANNOTATION
        if until_str:
            try:
                expires_at = datetime(
                    *map(int, until_str.split("-")),
                    tzinfo=timezone.utc,
                )
                kind = SuppressionKind.TIMED_DEFERRAL
            except (ValueError, TypeError):
                pass

        # Support comma-separated rule IDs
        rule_ids = [r.strip() for r in raw_rule_ids.split(",")]
        for rule_id in rule_ids:
            if not rule_id:
                continue
            suppressions.append(
                FindingSuppression(
                    suppression_id=f"INLINE-{file_path}-{line_num}-{rule_id}-{uuid.uuid4().hex[:8]}",
                    kind=kind,
                    scope=SuppressionScope.RULE_IN_FILE,
                    target_rule_id=rule_id,
                    target_file_path=file_path,
                    reason=reason,
                    expires_at=expires_at,
                    is_active=True,
                )
            )

    return suppressions


def parse_config_suppressions(
    suppression_configs: list[dict],
) -> list[FindingSuppression]:
    """Parse suppression records from .codesentinel.yaml configuration.

    Args:
        suppression_configs: List of suppression dictionaries from config.

    Returns:
        List of FindingSuppression records.
    """
    suppressions: list[FindingSuppression] = []

    for idx, cfg in enumerate(suppression_configs):
        rule_id = cfg.get("rule_id")
        file_path = cfg.get("file")
        reason = cfg.get("reason", "")
        expires_str = cfg.get("expires")
        scope_str = cfg.get("scope", "").upper()
        fingerprint = cfg.get("fingerprint")

        # Determine scope
        if fingerprint:
            scope = SuppressionScope.FINDING
        elif scope_str == "RULE":
            scope = SuppressionScope.RULE
        elif scope_str == "FILE":
            scope = SuppressionScope.FILE
        elif rule_id and file_path:
            scope = SuppressionScope.RULE_IN_FILE
        elif rule_id:
            scope = SuppressionScope.RULE
        elif file_path:
            scope = SuppressionScope.FILE
        else:
            continue

        # Parse expiration
        expires_at: Optional[datetime] = None
        kind = SuppressionKind.CONFIG_EXCLUSION
        if expires_str:
            try:
                expires_at = datetime(
                    *map(int, str(expires_str).split("-")),
                    tzinfo=timezone.utc,
                )
                kind = SuppressionKind.TIMED_DEFERRAL
            except (ValueError, TypeError):
                pass

        suppressions.append(
            FindingSuppression(
                suppression_id=f"CONFIG-{idx}-{rule_id or 'ALL'}-{uuid.uuid4().hex[:8]}",
                kind=kind,
                scope=scope,
                target_rule_id=rule_id,
                target_file_path=file_path,
                target_fingerprint=fingerprint,
                reason=reason,
                expires_at=expires_at,
                is_active=True,
            )
        )

    return suppressions


def _comment_prefixes_for_language(language: str) -> list[str]:
    """Return recognized comment prefixes for the given language."""
    lang_upper = language.upper()
    if lang_upper in ("JAVASCRIPT", "TYPESCRIPT", "JS", "TS"):
        return ["//", "/*", "*"]
    elif lang_upper == "PYTHON":
        return ["#"]
    else:
        # Default: support both styles
        return ["#", "//"]
