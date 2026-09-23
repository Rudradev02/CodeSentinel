"""Phase 5 tests for Finding, SourceLocation, and RuleDefinition models."""

from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    RuleDefinition,
    RuleMetadata,
    SourceLocation,
)
from analyzer.rules.registry import RuleRegistry


def test_source_location_optional_end_coordinates_and_aliases():
    """Verify SourceLocation allows None for end coordinates and provides aliases."""
    loc = SourceLocation(
        file_path="src/app.py",
        line_start=10,
        line_end=None,
        col_start=4,
        col_end=None,
    )
    assert loc.file_path == "src/app.py"
    assert loc.file == "src/app.py"
    assert loc.line_start == 10
    assert loc.start_line == 10
    assert loc.col_start == 4
    assert loc.start_column == 4
    assert loc.line_end is None
    assert loc.end_line is None
    assert loc.col_end is None
    assert loc.end_column is None

    # Test constructing with aliases
    loc2 = SourceLocation.model_validate({
        "file": "src/module.ts",
        "start_line": 25,
        "start_column": 8,
        "end_line": 30,
        "end_column": 12,
    })
    assert loc2.file_path == "src/module.ts"
    assert loc2.line_start == 25
    assert loc2.col_start == 8
    assert loc2.line_end == 30
    assert loc2.col_end == 12


def test_finding_phase5_enhanced_fields_and_properties():
    """Verify Finding supports message, explanation, evidence, title, and coordinate properties."""
    loc = SourceLocation(file_path="app/test.py", line_start=15, col_start=2)
    finding = Finding(
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secrets & High-Entropy Credentials",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="api_key = 'AKI...12'",
        description="Hardcoded credential detected.",
        remediation="Extract to environment variable.",
        message="Hardcoded secret in 'api_key'",
        explanation="Detected high-entropy credential string.",
        evidence={"variable_name": "api_key", "secret_preview": "AKI...12"},
    )
    assert finding.message == "Hardcoded secret in 'api_key'"
    assert finding.explanation == "Detected high-entropy credential string."
    assert finding.evidence["variable_name"] == "api_key"
    assert finding.file == "app/test.py"
    assert finding.title == "Hardcoded Secrets & High-Entropy Credentials"
    assert finding.start_line == 15
    assert finding.start_column == 2
    assert finding.end_line is None
    assert finding.end_column is None


def test_rule_definition_and_registry_metadata():
    """Verify RuleDefinition supports rationale and supported_languages, and registry metadata is valid."""
    registry = RuleRegistry(load_defaults=True)
    defs = registry.get_rule_definitions()

    assert len(defs) == 27, f"Expected 27 registered rules, got {len(defs)}"

    # Ensure all rule IDs are unique
    rule_ids = [d.rule_id for d in defs]
    assert len(rule_ids) == len(set(rule_ids))

    # Ensure RuleMetadata is an alias for RuleDefinition
    assert RuleMetadata is RuleDefinition

    for d in defs:
        assert d.rule_id.startswith(("SEC-", "ARC-"))
        assert len(d.name) > 3
        assert len(d.description) > 10
        assert len(d.remediation) > 10
        assert d.rationale is not None, f"Rule {d.rule_id} is missing rationale"
        assert len(d.rationale) > 10
        assert isinstance(d.supported_languages, list)
        assert d.severity in FindingSeverity
        assert d.confidence in FindingConfidence
