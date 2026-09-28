"""Pure-Python OpenXML (.xlsx) multi-tab compliance workbook generator (Phase 26).

Zero external dependencies: uses Python standard library `zipfile` and XML formatting.
Generates valid Microsoft Excel / LibreOffice Calc / Google Sheets workbooks.
"""

from __future__ import annotations

import io
from typing import Any, Optional
from xml.sax.saxutils import escape
import zipfile

from analyzer.compliance.catalogs import ALL_COMPLIANCE_CONTROLS
from analyzer.compliance.models import ComplianceAssessmentSuite, ComplianceStatus
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter


class ExcelWorkbookBuilder:
    """Constructs a multi-tab OpenXML (.xlsx) zip package in pure Python."""

    def __init__(self):
        self.sheets: list[tuple[str, list[list[Any]]]] = []

    def add_sheet(self, title: str, rows: list[list[Any]]) -> None:
        """Add a named worksheet with tabular row data."""
        clean_title = title[:31].replace(":", "_").replace("/", "_").replace("\\", "_")
        self.sheets.append((clean_title, rows))

    def _col_name(self, col_idx: int) -> str:
        """Convert 0-indexed column integer to Excel column letters (A, B, ..., Z, AA, AB...)."""
        result = []
        col_idx += 1
        while col_idx > 0:
            col_idx, rem = divmod(col_idx - 1, 26)
            result.append(chr(65 + rem))
        return "".join(reversed(result))

    def _generate_sheet_xml(self, rows: list[list[Any]]) -> str:
        """Generate sheet XML representation."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
            '<sheetData>',
        ]

        for row_idx, row in enumerate(rows, start=1):
            lines.append(f'<row r="{row_idx}">')
            for col_idx, val in enumerate(row):
                col_letter = self._col_name(col_idx)
                cell_ref = f"{col_letter}{row_idx}"
                if val is None:
                    continue
                elif isinstance(val, (int, float)):
                    lines.append(f'<c r="{cell_ref}"><v>{val}</v></c>')
                elif isinstance(val, bool):
                    lines.append(f'<c r="{cell_ref}" t="b"><v>{1 if val else 0}</v></c>')
                else:
                    escaped_str = escape(str(val))
                    lines.append(
                        f'<c r="{cell_ref}" t="inlineStr"><is><t>{escaped_str}</t></is></c>'
                    )
            lines.append('</row>')

        lines.append('</sheetData>')
        lines.append('</worksheet>')
        return "".join(lines)

    def build_bytes(self) -> bytes:
        """Compile workbook into in-memory OpenXML ZIP archive bytes."""
        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. [Content_Types].xml
            ct_lines = [
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
                '<Default Extension="xml" ContentType="application/xml"/>',
                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
                '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
            ]
            for i in range(1, len(self.sheets) + 1):
                ct_lines.append(
                    f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
                    f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                )
            ct_lines.append('</Types>')
            zf.writestr("[Content_Types].xml", "".join(ct_lines))

            # 2. _rels/.rels
            root_rels = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                'Target="xl/workbook.xml"/>'
                '</Relationships>'
            )
            zf.writestr("_rels/.rels", root_rels)

            # 3. xl/workbook.xml
            wb_lines = [
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
                '<sheets>',
            ]
            for i, (name, _) in enumerate(self.sheets, start=1):
                escaped_name = escape(name)
                wb_lines.append(f'<sheet name="{escaped_name}" sheetId="{i}" r:id="rId{i}"/>')
            wb_lines.append('</sheets>')
            wb_lines.append('</workbook>')
            zf.writestr("xl/workbook.xml", "".join(wb_lines))

            # 4. xl/_rels/workbook.xml.rels
            wb_rels_lines = [
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
            ]
            for i in range(1, len(self.sheets) + 1):
                wb_rels_lines.append(
                    f'<Relationship Id="rId{i}" '
                    f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                    f'Target="worksheets/sheet{i}.xml"/>'
                )
            wb_rels_lines.append(
                f'<Relationship Id="rId{len(self.sheets) + 1}" '
                f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
                f'Target="styles.xml"/>'
            )
            wb_rels_lines.append('</Relationships>')
            zf.writestr("xl/_rels/workbook.xml.rels", "".join(wb_rels_lines))

            # 5. xl/styles.xml (minimal default styles)
            styles_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>'
                '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
                '<borders count="1"><border><left/><right/><top/><bottom/></border></borders>'
                '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>'
                '</styleSheet>'
            )
            zf.writestr("xl/styles.xml", styles_xml)

            # 6. xl/worksheets/sheetN.xml
            for i, (_, rows) in enumerate(self.sheets, start=1):
                sheet_xml = self._generate_sheet_xml(rows)
                zf.writestr(f"xl/worksheets/sheet{i}.xml", sheet_xml)

        buffer.seek(0)
        return buffer.getvalue()


class ExcelReporter(BaseReporter):
    """Generates comprehensive, multi-tab OpenXML (.xlsx) compliance workbooks."""

    def _build_workbook(
        self,
        findings: list[Finding],
        compliance_suite: Optional[ComplianceAssessmentSuite] = None,
        attestation: Optional[Any] = None,
    ) -> ExcelWorkbookBuilder:
        wb = ExcelWorkbookBuilder()

        # Tab 1: Executive Summary
        exec_rows = [
            ["CodeSentinel Enterprise Regulatory Compliance Audit Workbook", ""],
            ["Generated At", compliance_suite.timestamp.isoformat() if compliance_suite else "N/A"],
            ["Repository Path", compliance_suite.repository_path if compliance_suite else "N/A"],
            ["Total Findings Detected", len(findings)],
            ["", ""],
            ["Framework", "Compliance Score (%)", "Status", "Compliant Controls", "Total Controls", "Unresolved Violations"],
        ]

        if compliance_suite:
            for fw_name, res in compliance_suite.framework_results.items():
                exec_rows.append([
                    fw_name,
                    f"{res.overall_score}%",
                    res.status.value,
                    res.compliant_controls,
                    res.total_controls,
                    res.unresolved_violations_count,
                ])
        wb.add_sheet("Executive Summary", exec_rows)

        # Tab 2: Control Matrix
        control_rows = [
            ["Framework", "Control ID", "Control Name", "Status", "Criticality", "Compliance Score", "Violations", "Exceptions", "Guidance"],
        ]
        if compliance_suite:
            for fw_name, res in compliance_suite.framework_results.items():
                for ce in res.control_evaluations:
                    control_rows.append([
                        fw_name,
                        ce.control.control_id,
                        ce.control.name,
                        ce.status.value,
                        ce.control.criticality.value,
                        ce.compliance_score,
                        ce.active_violation_count,
                        ce.suppressed_violation_count,
                        ce.control.guidance,
                    ])
        else:
            for fw, controls in ALL_COMPLIANCE_CONTROLS.items():
                for c in controls:
                    control_rows.append([
                        fw.value,
                        c.control_id,
                        c.name,
                        "UNKNOWN",
                        c.criticality.value,
                        1.0,
                        0,
                        0,
                        c.guidance,
                    ])
        wb.add_sheet("Control Matrix", control_rows)

        # Tab 3: Finding Inventory
        finding_rows = [
            ["Finding ID", "Rule ID", "Rule Name", "Severity", "Confidence", "File Path", "Line", "CWE", "OWASP", "Description", "Remediation"],
        ]
        for f in findings:
            fid = getattr(f, "fingerprint", None)
            stable_id = str(fid.stable_id) if (fid and hasattr(fid, "stable_id") and fid.stable_id) else f.id
            finding_rows.append([
                stable_id,
                f.rule_id,
                f.rule_name,
                f.severity.value,
                f.confidence.value,
                f.location.file_path,
                f.location.line_start,
                f.cwe_id or "N/A",
                f.owasp_category or "N/A",
                f.description,
                f.remediation,
            ])
        wb.add_sheet("Finding Inventory", finding_rows)

        # Tab 4: Suppressions & Deviations
        supp_rows = [
            ["Finding ID", "Rule ID", "File Path", "Line", "Suppression Reason", "Lifecycle State"],
        ]
        for f in findings:
            evidence = f.evidence or {}
            is_supp = (
                evidence.get("suppressed") is True
                or evidence.get("is_suppressed") is True
                or evidence.get("lifecycle_state") in ("SUPPRESSED", "DEFERRED")
            )
            if is_supp:
                supp_rows.append([
                    f.id,
                    f.rule_id,
                    f.location.file_path,
                    f.location.line_start,
                    evidence.get("suppression_reason", "Suppressed"),
                    evidence.get("lifecycle_state", "SUPPRESSED"),
                ])
        wb.add_sheet("Suppressions", supp_rows)

        # Tab 5: Cryptographic Attestation
        attest_rows = [
            ["Property", "Value"],
            ["Attestation Standard", "in-toto v1.0 / DSSE"],
            ["Verification Engine", "CodeSentinel HMAC-SHA256 / Ed25519"],
            ["Config Digest", compliance_suite.config_digest if compliance_suite else "N/A"],
            ["Git Commit", compliance_suite.git_commit_hash if compliance_suite else "N/A"],
        ]
        if attestation and hasattr(attestation, "signatures"):
            for idx, sig in enumerate(attestation.signatures):
                attest_rows.append([f"Signature #{idx + 1} Key ID", sig.get("keyid", "N/A")])
                attest_rows.append([f"Signature #{idx + 1} Hash", sig.get("sig", "N/A")[:32] + "..."])
        wb.add_sheet("Attestation", attest_rows)

        return wb

    def render(self, result: AnalysisResult) -> bytes:
        """Render an AnalysisResult into raw XLSX binary bytes."""
        findings = list(result.findings)
        wb = self._build_workbook(findings=findings)
        return wb.build_bytes()

    def render_compliance(self, suite: Any) -> bytes:
        """Render a ComplianceAssessmentSuite into raw XLSX binary bytes."""
        findings: list[Finding] = []
        if hasattr(suite, "framework_results"):
            for res in suite.framework_results.values():
                for ce in res.control_evaluations:
                    findings.extend(ce.violating_findings)
                    findings.extend(ce.suppressed_findings)

        unique_findings = {f.id: f for f in findings}
        wb = self._build_workbook(
            findings=list(unique_findings.values()),
            compliance_suite=suite if isinstance(suite, ComplianceAssessmentSuite) else None,
        )
        return wb.build_bytes()
