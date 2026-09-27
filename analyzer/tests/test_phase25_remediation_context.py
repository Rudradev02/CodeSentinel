"""Phase 25 tests — Contextual remediation context builder."""

import pytest

from analyzer.rules.remediation import (
    RemediationContext,
    RemediationContextBuilder,
    REMEDIATION_TEMPLATES,
)
from analyzer.models.findings import Finding, SourceLocation, FindingCategory, EvidenceType, FindingSeverity, FindingConfidence
from analyzer.models.evidence import TaintSourceEvidence, TaintSinkEvidence, SanitizerEvidence, SecurityEvidenceChain


def _make_finding(rule_id="SEC-PY-005", remediation="Use parameterized queries"):
    return Finding(
        rule_id=rule_id,
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="src/db.py", line_start=10),
        code_snippet="cursor.execute(query)",
        description="SQL injection",
        remediation=remediation,
    )


class TestRemediationContextBuilder:
    """Test contextual remediation builder."""

    def test_static_remediation_passthrough(self):
        """Static remediation from finding is included in context."""
        finding = _make_finding()
        ctx = RemediationContextBuilder.build(finding)
        assert ctx.static_remediation == "Use parameterized queries"

    def test_framework_specific_guidance_flask(self):
        """Flask-specific remediation for SQL injection policy."""
        finding = _make_finding()
        ctx = RemediationContextBuilder.build(finding, framework="FLASK", policy_id="POL-SQL-01")
        assert ctx.framework_guidance is not None
        assert "Flask" in ctx.framework_guidance
        assert ctx.framework == "FLASK"

    def test_framework_specific_guidance_django(self):
        """Django-specific remediation for SQL injection policy."""
        finding = _make_finding()
        ctx = RemediationContextBuilder.build(finding, framework="DJANGO", policy_id="POL-SQL-01")
        assert ctx.framework_guidance is not None
        assert "Django" in ctx.framework_guidance

    def test_framework_fallback_guidance(self):
        """Generic remediation when no framework-specific template exists."""
        finding = _make_finding()
        ctx = RemediationContextBuilder.build(finding, framework=None, policy_id="POL-SQL-01")
        assert ctx.framework_guidance is not None
        assert "parameterized" in ctx.framework_guidance.lower()

    def test_evidence_based_guidance(self):
        """Evidence chain produces taint path narrative."""
        finding = _make_finding()
        chain = SecurityEvidenceChain(
            taint_source=TaintSourceEvidence(
                source_category="HTTP_REQUEST_PARAM",
                file_path="src/views.py",
                line=15,
                expression="request.args['id']",
            ),
            taint_sink=TaintSinkEvidence(
                sink_category="SQL_EXECUTE",
                rule_id="SEC-PY-005",
                file_path="src/db.py",
                line=31,
                callee_name="cursor.execute",
            ),
            chain_depth=2,
        )
        ctx = RemediationContextBuilder.build(finding, evidence_chain=chain)
        assert ctx.evidence_guidance is not None
        assert "request.args['id']" in ctx.evidence_guidance
        assert "cursor.execute" in ctx.evidence_guidance

    def test_incompatible_sanitizer_warning(self):
        """Incompatible sanitizer generates warning."""
        finding = _make_finding()
        chain = SecurityEvidenceChain(
            taint_source=TaintSourceEvidence(
                source_category="HTTP_REQUEST_PARAM",
                file_path="src/views.py",
                line=15,
                expression="request.args['q']",
            ),
            taint_sink=TaintSinkEvidence(
                sink_category="SQL_EXECUTE",
                rule_id="SEC-PY-005",
                file_path="src/db.py",
                line=31,
                callee_name="cursor.execute",
            ),
            sanitizer_evaluation=SanitizerEvidence(
                sanitizer_id="html.escape",
                effective_categories=["DOM_INJECTION"],
                file_path="src/db.py",
                line=25,
                expression="html.escape(user_input)",
                is_category_compatible=False,
                incompatible_reason="html.escape is not effective against SQL injection",
            ),
        )
        ctx = RemediationContextBuilder.build(finding, evidence_chain=chain, policy_id="POL-SQL-01")
        assert ctx.incompatible_sanitizer_warning is not None
        assert "html.escape" in ctx.incompatible_sanitizer_warning

    def test_suggested_sanitizers_for_sql(self):
        """SQL injection policy suggests appropriate sanitizers."""
        finding = _make_finding()
        chain = SecurityEvidenceChain(
            taint_source=TaintSourceEvidence(
                source_category="HTTP_REQUEST_PARAM",
                file_path="src/views.py",
                line=15,
                expression="request.args['q']",
            ),
            taint_sink=TaintSinkEvidence(
                sink_category="SQL_EXECUTE",
                rule_id="SEC-PY-005",
                file_path="src/db.py",
                line=31,
                callee_name="cursor.execute",
            ),
        )
        ctx = RemediationContextBuilder.build(finding, evidence_chain=chain, policy_id="POL-SQL-01")
        assert len(ctx.suggested_sanitizers) > 0
        assert any("param" in s.lower() for s in ctx.suggested_sanitizers)
