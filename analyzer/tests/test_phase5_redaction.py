"""Phase 5 tests for secret redaction function and rule-level redaction guarantees."""

from analyzer.models.results import AnalysisResult, AnalysisMetadata, RepositoryInfo, SecuritySummary, ArchitectureSummary
from analyzer.reporting.json_reporter import JsonReporter
from analyzer.reporting.terminal import TerminalReporter
from analyzer.rules.entropy import redact_secret
from analyzer.security.python.sec_py_001_secrets import RuleSecPy001


def test_redact_secret_helper():
    """Verify deterministic redaction behaviour."""
    # Short secrets: masked with ***
    assert redact_secret("short") == "***"
    assert redact_secret("123456") == "***"

    # Longer secrets: prefix (3) + ... + suffix (2)
    assert redact_secret("AKIAIOSFODNN7EXAMPLE12") == "AKI...12"
    assert redact_secret("custom_mock_secret_token_1234567890_abcdef") == "cus...ef"


def test_secrets_never_leak_in_reports():
    """Verify full secret literals never appear in TerminalReporter or JsonReporter output."""
    raw_secret = "AKIAIOSFODNN7EXAMPLE12"
    rule = RuleSecPy001()
    findings = rule.analyze("secrets.py", f'aws_secret_access_key = "{raw_secret}"')

    assert len(findings) == 1
    finding = findings[0]

    result = AnalysisResult(
        repository=RepositoryInfo(
            name="test-repo",
            local_path="/repo",
            total_files=1,
            total_loc=1,
        ),
        metadata=AnalysisMetadata(
            engine_version="0.1.0",
            duration_seconds=0.01,
        ),
        security_findings=[finding],
        architecture_findings=[],
        security_summary=SecuritySummary(total=1, high=1, deterministic_count=1),
        architecture_summary=ArchitectureSummary(total_modules=1),
    )

    # Terminal report
    term_output = TerminalReporter().render(result)
    assert raw_secret not in term_output
    assert "AKI...12" in term_output

    # JSON report
    json_output = JsonReporter().render(result)
    assert raw_secret not in json_output
    assert "AKI...12" in json_output
