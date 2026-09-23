"""Unit tests for Phase 12 pre-prompt SecretScrubber service."""

from backend.app.services.ai.scrubber import (
    REDACTED_AUTH_HEADER,
    REDACTED_AWS_KEY,
    REDACTED_GITHUB_TOKEN,
    REDACTED_PASSWORD,
    REDACTED_PRIVATE_KEY,
    REDACTED_SECRET,
    REDACTED_SLACK_TOKEN,
    REDACTED_TOKEN,
    SecretScrubber,
)


def test_scrub_cloud_api_keys():
    """Verify known cloud and API provider keys are redacted into canonical tokens."""
    dummy_aws = "".join(["AKIA", "1234567890", "ABCDEF"])
    aws_text = f"aws_key = '{dummy_aws}'"
    assert SecretScrubber.scrub(aws_text) == f"aws_key = '{REDACTED_AWS_KEY}'"

    dummy_gh = "".join(["ghp_", "1234567890abcdef", "1234567890abcdef", "1234"])
    gh_text = f"github_token = '{dummy_gh}'"
    assert SecretScrubber.scrub(gh_text) == f"github_token = '{REDACTED_GITHUB_TOKEN}'"

    dummy_slack = "-".join(["xoxb", "123456789012", "123456789012", "abcdef1234567890abcdef12"])
    slack_text = f"webhook = '{dummy_slack}'"
    assert SecretScrubber.scrub(slack_text) == f"webhook = '{REDACTED_SLACK_TOKEN}'"

    dummy_openai = "".join(["sk-", "1234567890abcdef", "1234567890abcdef", "1234"])
    openai_text = f"sk_token = '{dummy_openai}'"
    assert SecretScrubber.scrub(openai_text) == f"sk_token = '{REDACTED_SECRET}'"


def test_scrub_database_urls():
    """Verify database connection strings with passwords are redacted."""
    pg_url = "DATABASE_URL = 'postgresql://admin:superSecretPassword123@db.example.com:5432/production'"
    scrubbed = SecretScrubber.scrub(pg_url)
    assert "superSecretPassword123" not in scrubbed
    assert REDACTED_PASSWORD in scrubbed
    assert "postgresql://admin:[REDACTED_PASSWORD]@" in scrubbed

    mongo_url = "mongo = 'mongodb+srv://root:P@ssw0rd99!@cluster0.mongodb.net/test'"
    scrubbed_mongo = SecretScrubber.scrub(mongo_url)
    assert "P@ssw0rd99!" not in scrubbed_mongo
    assert "mongodb+srv://root:[REDACTED_PASSWORD]@" in scrubbed_mongo


def test_scrub_bearer_tokens_and_auth_headers():
    """Verify Authorization headers and bearer tokens are sanitized."""
    header = 'headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"} '
    scrubbed = SecretScrubber.scrub(header)
    assert REDACTED_TOKEN in scrubbed or REDACTED_AUTH_HEADER in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed


def test_scrub_private_key_blocks():
    """Verify RSA/EC private key blocks are replaced in full."""
    key_block = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1234567890abcdef1234567890abcdef1234567890abcdef
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef==
-----END RSA PRIVATE KEY-----"""
    scrubbed = SecretScrubber.scrub(key_block)
    assert scrubbed == REDACTED_PRIVATE_KEY
    assert "MIIEowIBAAKCAQEA0Y1234567890" not in scrubbed


def test_scrub_idempotency_and_safe_text():
    """Verify text without secrets is untouched, and re-scrubbing is idempotent."""
    safe_code = """
def calculate_area(width: float, height: float) -> float:
    return width * height
"""
    assert SecretScrubber.scrub(safe_code) == safe_code

    # Idempotency check on already scrubbed text
    sample = "api_key = '[REDACTED_SECRET]'"
    assert SecretScrubber.scrub(sample) == sample
