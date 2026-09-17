"""Tests for analyzer models, schemas, and rule interfaces."""

import json
import pytest
from pydantic import ValidationError

from analyzer.models.findings import (
    AIFindingEnrichment,
    AIValidationStatus,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    RuleDefinition,
    SourceLocation,
)
from analyzer.models.graph import (
    ArchitectureGraph,
    CircularDependency,
    CouplingMetrics,
    DependencyEdge,
    DependencyNode,
    ImportType,
)
from analyzer.models.results import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisStatus,
    ArchitectureSummary,
    RepositoryInfo,
    SecuritySummary,
)
from analyzer.security.base_rule import BaseSecurityRule
from analyzer.architecture.base_rule import BaseArchitectureRule


class MockSecurityRule(BaseSecurityRule):
    """Test rule implementing BaseSecurityRule."""
    rule_id = "SEC-TEST-001"
    name = "Test Security Rule"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.HIGH
    confidence = FindingConfidence.HIGH
    languages = ["python"]
    frameworks = ["django"]
    description = "Test rule description"
    remediation = "Test rule remediation"
    cwe_id = "CWE-798"
    owasp_category = "A07:2021"

    def analyze(self, file_path, content, ast_node=None):
        loc = SourceLocation(file_path=file_path, line_start=10, line_end=10)
        return [self.create_finding(location=loc, code_snippet="SECRET = 'test'")]


class MockArchitectureRule(BaseArchitectureRule):
    """Test rule implementing BaseArchitectureRule."""
    rule_id = "ARCH-TEST-001"
    name = "Test Circular Dependency"
    evidence_type = EvidenceType.DETERMINISTIC
    severity = FindingSeverity.MEDIUM
    confidence = FindingConfidence.HIGH
    description = "Detected cycle"
    remediation = "Break import cycle"

    def analyze(self, graph):
        loc = SourceLocation(file_path="pkg/a.py", line_start=1, line_end=1)
        return [self.create_finding(location=loc, code_snippet="import b")]


def test_source_location_validation():
    """Verify line start and end validation."""
    valid_loc = SourceLocation(file_path="app/main.py", line_start=10, line_end=12)
    assert valid_loc.line_start == 10
    assert valid_loc.line_end == 12

    # Single-line location
    single_line = SourceLocation(file_path="app/main.py", line_start=5, line_end=5)
    assert single_line.line_start == 5

    # Invalid line range (start > end)
    with pytest.raises(ValidationError):
        SourceLocation(file_path="app/main.py", line_start=20, line_end=10)


def test_finding_creation_and_evidence_types():
    """Verify finding creation across all three evidence types."""
    loc = SourceLocation(file_path="views.py", line_start=15, line_end=15)

    # 1. Deterministic finding
    f_det = Finding(
        rule_id="SEC-PY-003",
        rule_name="Unsafe Subprocess",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="subprocess.call(cmd, shell=True)",
        description="Shell execution enabled",
        remediation="Use list arguments",
        cwe_id="CWE-78",
    )
    assert f_det.evidence_type == EvidenceType.DETERMINISTIC

    # 2. Heuristic finding
    f_heur = Finding(
        rule_id="SEC-JS-006",
        rule_name="Suspicious localStorage",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.HEURISTIC,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        location=loc,
        code_snippet="localStorage.setItem('auth_token', token)",
        description="Token in localStorage",
        remediation="Use HttpOnly cookie",
    )
    assert f_heur.evidence_type == EvidenceType.HEURISTIC

    # 3. Empty snippet must raise ValidationError
    with pytest.raises(ValidationError):
        Finding(
            rule_id="SEC-PY-001",
            rule_name="Secret",
            category=FindingCategory.SECURITY,
            evidence_type=EvidenceType.DETERMINISTIC,
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            location=loc,
            code_snippet="   ",  # whitespace only
            description="desc",
            remediation="rem",
        )


def test_ai_enrichment_attachment():
    """Verify AI enrichment schema attachment without altering deterministic base."""
    loc = SourceLocation(file_path="config.py", line_start=1, line_end=1)
    finding = Finding(
        rule_id="SEC-PY-001",
        rule_name="Hardcoded Secret",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="API_KEY = 'super_secret'",
        description="Hardcoded API key",
        remediation="Use env var",
    )
    assert finding.ai_enrichment is None

    enrichment = AIFindingEnrichment(
        provider="openrouter",
        model="claude-3.5-sonnet",
        validation_status=AIValidationStatus.CONFIRMED,
        explanation="This API key is embedded directly in client settings.",
        remediation_suggestion="Move key to AWS Secrets Manager or env variable.",
        unified_diff="- API_KEY = 'super_secret'\n+ API_KEY = os.environ['API_KEY']",
        confidence=0.95,
    )
    finding.ai_enrichment = enrichment

    assert finding.ai_enrichment.validation_status == AIValidationStatus.CONFIRMED
    assert finding.ai_enrichment.provider == "openrouter"


def test_dependency_graph_models():
    """Verify graph nodes, edges, cycles, and metrics."""
    node_a = DependencyNode(
        id="app.main",
        file_path="app/main.py",
        module_name="app.main",
        language="python",
        loc=50,
        fan_in=0,
        fan_out=2,
    )
    node_b = DependencyNode(
        id="app.core",
        file_path="app/core.py",
        module_name="app.core",
        language="python",
        loc=30,
        fan_in=1,
        fan_out=0,
    )

    edge = DependencyEdge(
        source="app.main",
        target="app.core",
        import_type=ImportType.STATIC,
        is_circular=False,
        line_number=5,
    )

    metrics = CouplingMetrics(
        total_modules=2,
        total_edges=1,
        density=0.5,
        average_fan_in=0.5,
        average_fan_out=0.5,
        max_fan_out=2,
        circular_cycles_count=0,
    )

    graph = ArchitectureGraph(
        nodes=[node_a, node_b],
        edges=[edge],
        circular_dependencies=[],
        metrics=metrics,
    )

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.metrics.total_modules == 2


def test_full_analysis_result_roundtrip():
    """Verify serialization and deserialization of a complete AnalysisResult."""
    repo = RepositoryInfo(
        name="test-repo",
        local_path="/repos/test-repo",
        detected_languages={"Python": 10, "TypeScript": 5},
        detected_frameworks=["Flask", "React"],
        total_files=15,
        total_loc=1200,
    )

    sec_summary = SecuritySummary(
        total=1,
        high=1,
        deterministic_count=1,
    )

    arch_summary = ArchitectureSummary(
        total_modules=5,
        circular_dependencies_count=0,
        god_modules_count=0,
        total_findings=0,
    )

    result = AnalysisResult(
        repository=repo,
        status=AnalysisStatus.COMPLETED,
        security_summary=sec_summary,
        architecture_summary=arch_summary,
        security_findings=[],
        architecture_findings=[],
    )

    # Test serialization to JSON and back
    json_data = result.model_dump_json()
    loaded = AnalysisResult.model_validate_json(json_data)

    assert loaded.repository.name == "test-repo"
    assert loaded.status == AnalysisStatus.COMPLETED
    assert loaded.repository.detected_languages["Python"] == 10
    assert loaded.security_summary.deterministic_count == 1


def test_rule_base_classes():
    """Verify BaseSecurityRule and BaseArchitectureRule behavior."""
    sec_rule = MockSecurityRule()
    rule_def = sec_rule.get_definition()
    assert rule_def.rule_id == "SEC-TEST-001"
    assert rule_def.category == FindingCategory.SECURITY
    assert rule_def.evidence_type == EvidenceType.DETERMINISTIC

    findings = sec_rule.analyze("test.py", "SECRET = 'test'")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-TEST-001"
    assert findings[0].evidence_type == EvidenceType.DETERMINISTIC

    arch_rule = MockArchitectureRule()
    arch_def = arch_rule.get_definition()
    assert arch_def.rule_id == "ARCH-TEST-001"
    assert arch_def.category == FindingCategory.ARCHITECTURE

    arch_findings = arch_rule.analyze(ArchitectureGraph())
    assert len(arch_findings) == 1
    assert arch_findings[0].rule_id == "ARCH-TEST-001"


def test_analyzer_independence():
    """Verify that analyzer source modules do NOT import any backend, fastapi, or celery modules."""
    import sys
    from pathlib import Path

    analyzer_dir = Path(__file__).resolve().parent.parent
    forbidden_tokens = ["fastapi", "celery", "sqlalchemy", "backend."]

    for py_file in analyzer_dir.rglob("*.py"):
        # Skip test files themselves
        if "tests" in py_file.parts:
            continue
        content = py_file.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content.lower(), f"Forbidden token '{token}' found in {py_file}"

