"""Pre-prompt secret and credential scrubbing service.

Ensures no private keys, passwords, API keys, bearer tokens, or cloud credentials
leave the local boundary or reach external LLM endpoints.
"""

import re
from typing import List, Tuple

# Deterministic replacement tokens
REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"
REDACTED_PASSWORD = "[REDACTED_PASSWORD]"
REDACTED_AUTH_HEADER = "[REDACTED_AUTH_HEADER]"
REDACTED_PRIVATE_KEY = "[REDACTED_PRIVATE_KEY]"
REDACTED_AWS_KEY = "[REDACTED_AWS_KEY]"
REDACTED_GITHUB_TOKEN = "[REDACTED_GITHUB_TOKEN]"
REDACTED_SLACK_TOKEN = "[REDACTED_SLACK_TOKEN]"

# (Pattern, Replacement)
SCRUB_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # 1. Private Key Blocks (RSA, EC, DSA, OPENSSH)
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        REDACTED_PRIVATE_KEY,
    ),
    # 2. Database Connection URLs with Passwords (Postgres, MySQL, Mongo, Redis)
    (
        re.compile(r"postgres(ql)?:\/\/([^:]+):([^@\s\'\"]+)@", re.IGNORECASE),
        r"postgresql://\2:[REDACTED_PASSWORD]@",
    ),
    (
        re.compile(r"mysql:\/\/([^:]+):([^@\s\'\"]+)@", re.IGNORECASE),
        r"mysql://\2:[REDACTED_PASSWORD]@",
    ),
    (
        re.compile(r"mongodb(\+srv)?:\/\/([^:]+):([^@\s\'\"]+)@", re.IGNORECASE),
        r"mongodb\1://\2:[REDACTED_PASSWORD]@",
    ),
    (
        re.compile(r"redis:\/\/:([^@\s\'\"]+)@", re.IGNORECASE),
        r"redis://:[REDACTED_PASSWORD]@",
    ),
    # 3. Known Provider API Keys & Tokens
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED_AWS_KEY),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), REDACTED_GITHUB_TOKEN),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,72}"), REDACTED_SLACK_TOKEN),

    (re.compile(r"sk-[a-zA-Z0-9]{32,64}"), REDACTED_SECRET),
    (re.compile(r"sk_live_[a-zA-Z0-9]{24,64}"), REDACTED_SECRET),
    # 4. Bearer Tokens & Authorization Headers
    (
        re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}"),
        f"Bearer {REDACTED_TOKEN}",
    ),
    (
        re.compile(r"(?i)authorization[\s]*:[\s]*[\'\"][^\'\"]+[\'\"]"),
        f'Authorization: "{REDACTED_AUTH_HEADER}"',
    ),
    # 5. JWT Tokens (header.payload.signature)
    (
        re.compile(r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*"),
        REDACTED_TOKEN,
    ),
    # 6. Generic High-Entropy Assignments (e.g. api_key = "...", secret_token = '...')
    (
        re.compile(
            r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)[\s]*[=:]+[\s]*[\'"][A-Za-z0-9_\-\.]{8,}[\'"]'
        ),
        r'\1 = "[REDACTED_SECRET]"',
    ),
]


class SecretScrubber:
    """Sanitizes text and code context to ensure no sensitive credentials reach the LLM."""

    @classmethod
    def scrub(cls, text: str) -> str:
        """Replace all detected credentials and sensitive patterns with deterministic tokens."""
        if not text:
            return ""

        sanitized = text
        for pattern, replacement in SCRUB_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

        return sanitized

    @classmethod
    def contains_potential_secret(cls, text: str) -> bool:
        """Check whether any sensitive pattern matches in the text."""
        if not text:
            return False
        for pattern, _ in SCRUB_PATTERNS:
            if pattern.search(text):
                return True
        return False
