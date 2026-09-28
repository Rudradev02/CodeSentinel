"""Tests for pure-Python deterministic PDF compliance reporter."""

import pytest
from analyzer.compliance.evaluator import ComplianceEvaluator
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.reporting.pdf_reporter import PdfReporter, SimplePdfDocument


def test_simple_pdf_document_binary_structure():
    """Verify SimplePdfDocument compiles valid PDF 1.4 binary structure."""
    doc = SimplePdfDocument()
    lines = [f"Sample report line {i}" for i in range(10)]
    pdf_bytes = doc.generate("Title of Document", lines)

    assert pdf_bytes.startswith(b"%PDF-1.4\n")
    assert b"/Type /Catalog" in pdf_bytes
    assert b"/Type /Pages" in pdf_bytes
    assert b"/Type /Font" in pdf_bytes
    assert b"xref\n" in pdf_bytes
    assert pdf_bytes.rstrip().endswith(b"%%EOF")


def test_pdf_reporter_render_compliance():
    """Verify PdfReporter renders compliance suite into valid PDF document."""
    finding = Finding(
        rule_id="SEC-PY-005",
        rule_name="Raw SQL Query String Construction",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=SourceLocation(file_path="app/db.py", line_start=25),
        code_snippet="cursor.execute(sql)",
        description="SQL injection",
        remediation="Parameterize queries",
    )
    evaluator = ComplianceEvaluator()
    suite = evaluator.assess_suite([finding], repository_path="/test/repo")

    reporter = PdfReporter()
    pdf_bytes = reporter.render_compliance(suite)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"CodeSentinel Regulatory Compliance Audit Report" in pdf_bytes
    assert b"PCI_DSS_V4_0" in pdf_bytes
    assert b"%%EOF" in pdf_bytes
