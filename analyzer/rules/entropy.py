"""Shannon entropy calculation and secret detection helpers for CodeSentinel."""

import math
import re

# Known sensitive key prefixes (high confidence secrets regardless of entropy calculation)
KNOWN_SECRET_PREFIXES = (
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "AKIA",
    "ASIA",
    "django-insecure-",
    "xoxb-",
    "xoxp-",
    "glpat-",
)

# Placeholders and false-positive literals that should never be flagged as hardcoded secrets
BENIGN_SECRET_PLACEHOLDERS = {
    "",
    "change-me",
    "changeme",
    "your-secret-here",
    "your_secret_here",
    "your-api-key",
    "your_api_key",
    "replace_with_secret",
    "replace-me",
    "todo",
    "dummy",
    "dummy_secret",
    "test",
    "test_secret",
    "example",
    "localhost",
    "postgres",
    "admin",
    "password",
    "secret",
    "none",
    "null",
    "undefined",
    "00000000-0000-0000-0000-000000000000",
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.
    
    Higher values indicate greater information density and randomness.
    Typical English text: ~3.0 - 3.5.
    Cryptographic keys / hashes: ~4.0 - 5.5.
    
    Args:
        data: Input string.
        
    Returns:
        Shannon entropy in bits per character.
    """
    if not data:
        return 0.0

    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def is_likely_secret_string(value: str, min_length: int = 12, min_entropy: float = 3.8) -> bool:
    """Determine if a string value exhibits characteristics of a high-entropy secret.
    
    Conditions:
    1. Not in known benign placeholder set.
    2. Does not start with standard environment variable interpolation ($ or %).
    3. Either starts with a known secret prefix OR has length >= min_length and Shannon entropy >= min_entropy.
    """
    val_clean = value.strip().strip("'\"")
    if not val_clean:
        return False

    # Check benign placeholders
    if val_clean.lower() in BENIGN_SECRET_PLACEHOLDERS:
        return False

    # Check if value looks like a template/env reference: e.g. ${SECRET}, %(SECRET)s, env(SECRET)
    if (val_clean.startswith("${") and val_clean.endswith("}")) or (
        val_clean.startswith("$") and len(val_clean.split()) == 1
    ):
        return False

    # Check known secret prefixes
    for prefix in KNOWN_SECRET_PREFIXES:
        if val_clean.startswith(prefix):
            return True

    # Check length and Shannon entropy
    if len(val_clean) < min_length:
        return False

    entropy = calculate_shannon_entropy(val_clean)
    return entropy >= min_entropy


def redact_secret(secret: str) -> str:
    """Deterministically redact a secret string to prevent leaking sensitive credentials.
    
    Exposes only a small prefix and suffix (e.g. 'AKI...12') and masks the rest.
    Guarantees that full secret literals never appear in reports, logs, or evidence.
    """
    s = secret.strip().strip("'\"`")
    if len(s) <= 6:
        return "***"
    return f"{s[:3]}...{s[-2:]}"
