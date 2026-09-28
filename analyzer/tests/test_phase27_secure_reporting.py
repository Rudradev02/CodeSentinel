"""Test suite for Phase 27: Secure Reporting Standards (CWE-1236 Sanitization, Deterministic UUIDs, PDF wrapping)."""

import io
import uuid
import zipfile
import pytest

from analyzer.compliance.evaluator import ComplianceEvaluator
from analyzer.compliance.models import ComplianceFramework
from analyzer.reporting.cyclonedx_reporter import CycloneDxReporter, _generate_deterministic_cyclonedx_uuid
from analyzer.reporting.excel_reporter import ExcelReporter, sanitize_excel_cell
from analyzer.reporting.pdf_reporter import PdfReporter, _clean_pdf_text, _wrap_pdf_line


def test_excel_formula_injection_sanitization():
    """Verify CWE-1236 spreadsheet formula injection sanitization."""
    # Malicious formula prefixes
    assert sanitize_excel_cell("=1+1") == "'=1+1"
    assert sanitize_excel_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_excel_cell("-2+3") == "'-2+3"
    assert sanitize_excel_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_excel_cell("\tleading_tab") == "'\tleading_tab"
    assert sanitize_excel_cell("\rleading_cr") == "'\rleading_cr"

    # Non-formula strings
    assert sanitize_excel_cell("Safe String") == "Safe String"
    assert sanitize_excel_cell("12345") == "12345"

    # Non-string types
    assert sanitize_excel_cell(100) == 100
    assert sanitize_excel_cell(3.14) == 3.14
    assert sanitize_excel_cell(True) is True
    assert sanitize_excel_cell(None) == ""


def test_excel_xml_control_character_stripping():
    """Verify stripping of invalid XML 1.0 control characters."""
    dirty_cell = "Bad\x00Char\x08Text\x1bEsc"
    cleaned = sanitize_excel_cell(dirty_cell)
    assert "\x00" not in cleaned
    assert "\x08" not in cleaned
    assert "\x1b" not in cleaned
    assert cleaned == "BadCharTextEsc"


def test_excel_reporter_deterministic_zip_output():
    """Verify that ExcelReporter generates valid ZIP archives with deterministic 1980 file timestamps."""
    evaluator = ComplianceEvaluator(frameworks=[ComplianceFramework.PCI_DSS_V4_0])
    suite = evaluator.assess_suite(findings=[], repository_path="test/repo")
    reporter = ExcelReporter()
    excel_bytes = reporter.render_compliance(suite)

    assert isinstance(excel_bytes, bytes)
    assert excel_bytes.startswith(b"PK")

    # Read back as zip and inspect date_time
    with zipfile.ZipFile(io.BytesIO(excel_bytes)) as zf:
        infolist = zf.infolist()
        assert len(infolist) > 0
        for info in infolist:
            assert info.date_time == (1980, 1, 1, 0, 0, 0)


def test_cyclonedx_deterministic_uuid_v5():
    """Verify CycloneDX reporter generates deterministic UUID v5 serial numbers."""
    uuid_1 = _generate_deterministic_cyclonedx_uuid("CodeSentinel", "2026-09-28T12:00:00Z")
    uuid_2 = _generate_deterministic_cyclonedx_uuid("CodeSentinel", "2026-09-28T12:00:00Z")
    assert uuid_1 == uuid_2
    assert uuid_1.startswith("urn:uuid:")

    # Different repo or timestamp gives different UUID
    uuid_other = _generate_deterministic_cyclonedx_uuid("OtherRepo", "2026-09-28T12:00:00Z")
    assert uuid_other != uuid_1


def test_pdf_reporter_text_cleaning_and_line_wrapping():
    """Verify PDF unicode normalization and line wrapping (max 85 chars)."""
    # Unicode decomposition
    unicode_sample = "Café au lait – 100% Secure"
    cleaned = _clean_pdf_text(unicode_sample)
    assert all(ord(c) < 128 for c in cleaned)

    # Line wrapping
    long_line = "This is a very long line that exceeds eighty-five characters and needs to be wrapped gracefully into multiple lines without cutting off words arbitrarily."
    wrapped = _wrap_pdf_line(long_line, max_len=85)
    assert len(wrapped) > 1
    for seg in wrapped:
        assert len(seg) <= 85
