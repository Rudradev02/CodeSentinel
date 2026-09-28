"""Tests for pure-Python OpenXML Excel compliance workbook reporter."""

import io
import zipfile
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
from analyzer.models.results import AnalysisMetadata, AnalysisResult, RepositoryInfo
from analyzer.reporting.excel_reporter import ExcelReporter, ExcelWorkbookBuilder


def test_excel_workbook_builder_zip_structure():
    """Verify ExcelWorkbookBuilder generates valid OpenXML ZIP package with required parts."""
    builder = ExcelWorkbookBuilder()
    builder.add_sheet("TestSheet", [["Col A", "Col B"], [1, "Text with <special> & characters"]])
    xlsx_bytes = builder.build_bytes()

    assert len(xlsx_bytes) > 0
    # Must be valid zip
    assert xlsx_bytes[:4] == b"PK\x03\x04"

    with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "[Content_Types].xml" in namelist
        assert "_rels/.rels" in namelist
        assert "xl/workbook.xml" in namelist
        assert "xl/styles.xml" in namelist
        assert "xl/worksheets/sheet1.xml" in namelist

        # Inspect sheet XML
        sheet1_xml = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        assert "&lt;special&gt; &amp; characters" in sheet1_xml


def test_excel_reporter_render_compliance():
    """Verify ExcelReporter produces a 5-tab compliance audit workbook."""
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

    reporter = ExcelReporter()
    xlsx_data = reporter.render_compliance(suite)

    assert isinstance(xlsx_data, bytes)
    assert len(xlsx_data) > 0

    with zipfile.ZipFile(io.BytesIO(xlsx_data), "r") as zf:
        wb_xml = zf.read("xl/workbook.xml").decode("utf-8")
        assert "Executive Summary" in wb_xml
        assert "Control Matrix" in wb_xml
        assert "Finding Inventory" in wb_xml
        assert "Suppressions" in wb_xml
        assert "Attestation" in wb_xml
