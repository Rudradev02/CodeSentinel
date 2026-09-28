"""Deterministic pure-Python PDF 1.4 executive compliance report generator (Phase 26).

Zero external dependencies: directly compiles standard PDF 1.4 binary objects,
page trees, fonts, and text streams using Python standard library primitives.
"""

from __future__ import annotations

import io
from typing import Any, Optional

from analyzer.compliance.models import ComplianceAssessmentSuite
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter


class SimplePdfDocument:
    """Minimal, self-contained PDF 1.4 document compiler."""

    def __init__(self):
        self.objects: list[bytes] = []

    def _add_object(self, content: bytes) -> int:
        self.objects.append(content)
        return len(self.objects)

    def generate(
        self,
        title: str,
        lines: list[str],
    ) -> bytes:
        """Compile lines of text into a multi-page PDF 1.4 document."""
        # 1 line ~ 14pt leading, 45 lines per page max
        lines_per_page = 42
        pages_content: list[list[str]] = []
        for i in range(0, len(lines), lines_per_page):
            pages_content.append(lines[i : i + lines_per_page])

        if not pages_content:
            pages_content.append(["(No compliance data available)"])

        total_pages = len(pages_content)

        # Build stream contents for each page
        page_stream_ids: list[int] = []
        page_obj_ids: list[int] = []

        # We will allocate:
        # 1: Catalog
        # 2: Pages root
        # 3: Helvetica font
        # Next (2 * total_pages) objects: Page and Stream for each page.

        font_id = 3

        for page_idx, page_lines in enumerate(pages_content, start=1):
            stream_buf = io.BytesIO()
            stream_buf.write(b"BT\n")
            # Header font: F1 12pt
            stream_buf.write(f"/F1 14 Tf\n50 740 Td\n({title}) Tj\n".encode("latin-1", "replace"))
            stream_buf.write(f"/F1 9 Tf\n0 -16 Td\n(Page {page_idx} of {total_pages}) Tj\n".encode("latin-1", "replace"))
            stream_buf.write(b"/F1 10 Tf\n0 -24 Td\n")

            leading = 14
            for l in page_lines:
                # Sanitize text for PDF parenthesis escaping
                clean_l = l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                stream_buf.write(f"({clean_l}) Tj\n0 -{leading} Td\n".encode("latin-1", "replace"))

            stream_buf.write(b"ET\n")
            stream_bytes = stream_buf.getvalue()

            stream_obj = (
                f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
                + stream_bytes
                + b"\nendstream"
            )
            # Reserve placeholder
            page_stream_ids.append(len(self.objects) + 1)
            self._add_object(stream_obj)

        # Now assemble PDF structures
        # Object 1: Catalog (will be at index 0 after reordering)
        # To make object referencing predictable, let's assemble cleanly in a single pass.
        all_objects: list[bytes] = []

        # 1: Catalog -> Points to 2
        catalog_obj = b"<< /Type /Catalog /Pages 2 0 R >>"
        all_objects.append(catalog_obj)

        # 2: Pages root
        # Page object IDs will be 4, 6, 8, ...
        # Stream object IDs will be 5, 7, 9, ...
        page_ids = [4 + (i * 2) for i in range(total_pages)]
        kids_ref = " ".join(f"{pid} 0 R" for pid in page_ids)
        pages_root_obj = f"<< /Type /Pages /Kids [{kids_ref}] /Count {total_pages} >>".encode("ascii")
        all_objects.append(pages_root_obj)

        # 3: Helvetica font
        font_obj = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        all_objects.append(font_obj)

        # For each page:
        for idx in range(total_pages):
            page_id = page_ids[idx]
            stream_id = page_id + 1
            page_obj = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>"
            ).encode("ascii")
            all_objects.append(page_obj)

            # Stream
            page_lines = pages_content[idx]
            stream_buf = io.BytesIO()
            stream_buf.write(b"BT\n")
            stream_buf.write(f"/F1 13 Tf\n50 740 Td\n({title}) Tj\n".encode("latin-1", "replace"))
            stream_buf.write(f"/F1 8 Tf\n0 -14 Td\n(Page {idx + 1} of {total_pages}) Tj\n".encode("latin-1", "replace"))
            stream_buf.write(b"/F1 9 Tf\n0 -22 Td\n")

            for l in page_lines:
                clean_l = l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                stream_buf.write(f"({clean_l}) Tj\n0 -13 Td\n".encode("latin-1", "replace"))

            stream_buf.write(b"ET\n")
            sb = stream_buf.getvalue()
            st_obj = f"<< /Length {len(sb)} >>\nstream\n".encode("ascii") + sb + b"\nendstream"
            all_objects.append(st_obj)

        # Write output PDF
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = [0]
        for obj_idx, obj_data in enumerate(all_objects, start=1):
            offsets.append(out.tell())
            out.write(f"{obj_idx} 0 obj\n".encode("ascii"))
            out.write(obj_data)
            out.write(b"\nendobj\n")

        xref_pos = out.tell()
        out.write(f"xref\n0 {len(all_objects) + 1}\n".encode("ascii"))
        out.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode("ascii"))

        out.write(
            f"trailer\n<< /Size {len(all_objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii")
        )

        return out.getvalue()


class PdfReporter(BaseReporter):
    """Executive regulatory compliance PDF report generator."""

    def render(self, result: AnalysisResult) -> bytes:
        """Render standard AnalysisResult into PDF format."""
        doc = SimplePdfDocument()
        lines: list[str] = [
            f"Target Repository: {result.repository_path or 'N/A'}",
            f"Total Findings Detected: {len(result.findings)}",
            "",
            "FINDING SUMMARY:",
            "--------------------------------------------------------------------------------",
        ]
        for f in result.findings[:30]:
            lines.append(f"[{f.severity.value}] {f.rule_id}: {f.location.file_path}:{f.location.line_start}")
            lines.append(f"  Description: {f.description[:70]}")
            lines.append(f"  Remediation: {f.remediation[:70]}")
            lines.append("")

        return doc.generate("CodeSentinel Static Analysis Executive Summary", lines)

    def render_compliance(self, suite: Any) -> bytes:
        """Render a ComplianceAssessmentSuite into an executive regulatory compliance PDF."""
        doc = SimplePdfDocument()
        lines: list[str] = []

        if isinstance(suite, ComplianceAssessmentSuite):
            lines.append(f"Assessment Timestamp: {suite.timestamp.isoformat()}")
            lines.append(f"Target Repository: {suite.repository_path or 'N/A'}")
            lines.append(f"Git Commit Hash: {suite.git_commit_hash or 'HEAD'}")
            lines.append(f"Configuration Digest: {suite.config_digest or 'N/A'}")
            lines.append("")
            lines.append("EXECUTIVE REGULATORY COMPLIANCE SCORECARD:")
            lines.append("================================================================================")
            for fw, res in suite.framework_results.items():
                lines.append(f"Standard: {fw}")
                lines.append(f"  Overall Score: {res.overall_score}% | Status: {res.status.value}")
                lines.append(
                    f"  Controls: {res.compliant_controls} Compliant, {res.partial_controls} Partial, {res.non_compliant_controls} Non-Compliant"
                )
                lines.append(
                    f"  Violations: {res.unresolved_violations_count} Active, {res.suppressed_exceptions_count} Suppressed"
                )
                lines.append("")

            lines.append("CONTROL AUDIT DETAILS:")
            lines.append("--------------------------------------------------------------------------------")
            for fw, res in suite.framework_results.items():
                lines.append(f"[{fw}] Controls:")
                for ce in res.control_evaluations:
                    lines.append(
                        f"  * {ce.control.control_id} - {ce.control.name} [{ce.status.value}] (Score: {ce.compliance_score})"
                    )
                    if ce.violating_findings:
                        lines.append(f"    Active Violations: {len(ce.violating_findings)}")
                    if ce.suppressed_findings:
                        lines.append(f"    Authorized Exceptions: {len(ce.suppressed_findings)}")
                lines.append("")

            lines.append("CRYPTOGRAPHIC ATTESTATION SEAL:")
            lines.append("--------------------------------------------------------------------------------")
            lines.append("This document reflects an in-toto / DSSE cryptographically sealed scan record.")
            lines.append("Verify authenticity via: codesentinel compliance verify-attestation")
        else:
            lines.append("No compliance assessment suite data provided.")

        return doc.generate("CodeSentinel Regulatory Compliance Audit Report", lines)
