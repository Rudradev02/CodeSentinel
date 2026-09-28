"""End-to-end integration test for Phase 26 Enterprise Compliance & Governance pipeline."""

from pathlib import Path
import pytest
from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.reporting.cyclonedx_reporter import CycloneDxReporter
from analyzer.reporting.excel_reporter import ExcelReporter
from analyzer.reporting.pdf_reporter import PdfReporter


def test_phase26_end_to_end_pipeline(tmp_path: Path):
    """Verify complete static analysis pipeline with rule pack composition, compliance evaluation, and attestation."""
    # Create sample repository with vulnerable code
    db_file = tmp_path / "db.py"
    db_file.write_text(
        "import sqlite3\n"
        "def query_user(uid):\n"
        "    conn = sqlite3.connect('test.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
        encoding="utf-8",
    )

    config = AnalysisConfig(
        rule_packs=["pci-dss-v4"],
        compliance_frameworks=["PCI_DSS_V4_0", "HIPAA_SECURITY"],
        enable_attestation=True,
        signing_key="integration-test-secret-key",
    )

    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=config)

    assert result.status.value == "COMPLIANT" or result.status.value == "COMPLETED"
    assert len(result.findings) > 0

    # Verify compliance assessment suite
    assert result.compliance is not None
    assert "PCI_DSS_V4_0" in result.compliance.framework_results
    pci_res = result.compliance.framework_results["PCI_DSS_V4_0"]
    assert pci_res.status.value == "NON_COMPLIANT"
    assert pci_res.unresolved_violations_count > 0

    # Verify attestation
    assert result.attestation is not None
    assert len(result.attestation.signatures) == 1
    assert result.attestation.payloadType == "application/vnd.in-toto+json"

    # Verify multi-format reporting on the result
    cyclonedx_out = CycloneDxReporter().render(result)
    assert "CycloneDX" in cyclonedx_out
    assert "vulnerabilities" in cyclonedx_out

    excel_bytes = ExcelReporter().render_compliance(result.compliance)
    assert isinstance(excel_bytes, bytes)
    assert excel_bytes[:4] == b"PK\x03\x04"

    pdf_bytes = PdfReporter().render_compliance(result.compliance)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
