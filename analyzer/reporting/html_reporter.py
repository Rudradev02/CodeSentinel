"""Standalone interactive single-file HTML report generator (Phase 14)."""

import html
from typing import Optional

from analyzer.models.comparison import ComparisonResult, FindingTransition
from analyzer.models.findings import FindingSeverity
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#94a3b8",
}

SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 1,
    FindingSeverity.HIGH: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 4,
    FindingSeverity.INFO: 5,
}


def _esc(val: Optional[str]) -> str:
    """Safely escape text for HTML attribute and body injection."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


class HtmlReporter(BaseReporter):
    """Generates 100% self-contained, zero-network-dependency HTML reports."""

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult into a complete standalone HTML document."""
        repo = result.repository
        meta = result.metadata
        health = result.health
        sec = result.security_summary
        arch = result.architecture_summary

        score = health.overall_score if health else 100.0
        grade = health.overall_grade if health else "A"
        sec_score = health.security_posture.score if health and health.security_posture else 100.0
        arch_score = health.architecture_health.score if health and health.architecture_health else 100.0

        all_findings = sorted(
            result.security_findings + result.architecture_findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 99),
                f.location.file_path,
                f.location.line_start or 0,
                f.rule_id,
            ),
        )

        # Build table rows
        rows_html = []
        for idx, f in enumerate(all_findings, start=1):
            sev_str = f.severity.value
            sev_color = SEVERITY_COLORS.get(sev_str, "#94a3b8")
            loc_str = f"{f.location.file_path}:{f.location.line_start or 1}"
            
            taint_html = ""
            if f.evidence and isinstance(f.evidence, dict) and f.evidence.get("flow_type") in ("INTRA_PROCEDURAL_TAINT", "INTER_PROCEDURAL_TAINT"):
                path_summary = f.evidence.get("path_summary", f.message)
                is_inter = f.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT"
                call_chain_html = ""
                if is_inter and "call_chain" in f.evidence and isinstance(f.evidence["call_chain"], list):
                    steps_html = []
                    for s_i, step in enumerate(f.evidence["call_chain"], 1):
                        caller = _esc(str(step.get("caller_function", "?")))
                        callee = _esc(str(step.get("callee_function", "?")))
                        caller_f = _esc(str(step.get("caller_file", "?")))
                        line = step.get("call_site_line", "?")
                        action = _esc(str(step.get("taint_action", "")))
                        steps_html.append(f"<div style='margin-bottom:0.2rem;'>{s_i}. <code>{caller}()</code> &rarr; <code>{callee}()</code> at <code>{caller_f}:{line}</code> ({action})</div>")
                    call_chain_html = f"<div style='margin-top:0.4rem; padding:0.4rem; background:#1e1b4b; border-radius:0.25rem; font-size:0.75rem;'>{''.join(steps_html)}</div>"

                summary_label = "View Cross-Function Taint Trace" if is_inter else "View Data-Flow Taint Trace"
                taint_html = f"""
                <details class="taint-details">
                    <summary>{summary_label}</summary>
                    <pre class="taint-code">{_esc(path_summary)}</pre>
                    {call_chain_html}
                </details>
                """

            rows_html.append(f"""
            <tr class="finding-row sev-{sev_str.lower()}" data-sev="{sev_str}" data-cat="{f.category.value}">
                <td><span class="badge" style="background:{sev_color}20; color:{sev_color}; border:1px solid {sev_color}50;">{sev_str}</span></td>
                <td><strong>{_esc(f.rule_id)}</strong><div class="muted-sm">{_esc(f.rule_name)}</div></td>
                <td><code class="code-loc">{_esc(loc_str)}</code></td>
                <td>
                    <div class="finding-msg">{_esc(f.message or f.description)}</div>
                    {f'<pre class="code-snip">{_esc(f.code_snippet)}</pre>' if f.code_snippet else ''}
                    {taint_html}
                    <div class="remediation"><strong>Remediation:</strong> {_esc(f.remediation)}</div>
                </td>
            </tr>
            """)

        duration_sec = meta.duration_seconds if meta and meta.duration_seconds is not None else 0.0
        total_loc = repo.total_loc if repo and repo.total_loc is not None else 0
        total_files = repo.total_files if repo and repo.total_files is not None else 0
        engine_ver = meta.engine_version if meta and meta.engine_version else "0.1.0"
        repo_name = repo.name if repo and repo.name else "Codebase"
        repo_local_path = repo.local_path if repo and repo.local_path else (result.target_path or "")
        commit_str = repo.commit_hash[:10] if repo and repo.commit_hash else 'N/A'
        branch_str = repo.branch if repo and repo.branch else 'N/A'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>CodeSentinel Audit - {_esc(repo_name)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #6366f1;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.75rem; }}
        .meta-bar {{ display: flex; gap: 1.5rem; color: var(--text-muted); font-size: 0.875rem; }}
        .grid-kpi {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; }}
        .card-title {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .card-value {{ font-size: 2rem; font-weight: 700; color: #fff; }}
        .card-sub {{ font-size: 0.875rem; color: var(--text-muted); margin-top: 0.25rem; }}
        .grade-a {{ color: #10b981; }}
        .grade-b {{ color: #3b82f6; }}
        .grade-c {{ color: #f59e0b; }}
        .grade-d {{ color: #f97316; }}
        .grade-f {{ color: #ef4444; }}
        .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: var(--surface); border-radius: 0.5rem; overflow: hidden; }}
        th, td {{ padding: 0.875rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.875rem; }}
        th {{ background: #182234; color: var(--text-muted); font-weight: 600; }}
        .code-loc {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #a5b4fc; background: #0b1120; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.8rem; }}
        .code-snip {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b1120; padding: 0.5rem; border-radius: 0.25rem; margin: 0.5rem 0; overflow-x: auto; color: #cbd5e1; font-size: 0.8rem; }}
        .remediation {{ color: #38bdf8; font-size: 0.8rem; margin-top: 0.25rem; }}
        .muted-sm {{ font-size: 0.75rem; color: var(--text-muted); }}
        .taint-details {{ margin-top: 0.5rem; font-size: 0.8rem; }}
        .taint-details summary {{ cursor: pointer; color: #c084fc; }}
        .taint-code {{ background: #130e24; color: #e9d5ff; padding: 0.5rem; border-radius: 0.25rem; margin-top: 0.25rem; font-family: monospace; font-size: 0.75rem; white-space: pre-wrap; }}
        .filter-controls {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; }}
        .filter-btn {{ background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 0.4rem 0.8rem; border-radius: 0.375rem; cursor: pointer; font-size: 0.8rem; }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ CodeSentinel Report: {_esc(repo_name)}</h1>
                <div class="meta-bar">
                    <span>Target: <code>{_esc(repo_local_path)}</code></span>
                    <span>Commit: <code>{_esc(commit_str)}</code></span>
                    <span>Branch: <code>{_esc(branch_str)}</code></span>
                    <span>Duration: <strong>{duration_sec:.2f}s</strong></span>
                </div>
            </div>
            <div>
                <span class="badge" style="background:var(--accent)30; color:#a5b4fc; border:1px solid var(--accent); font-size:0.9rem; padding:0.4rem 0.8rem;">
                    v{engine_ver}
                </span>
            </div>
        </header>

        <section class="grid-kpi">
            <div class="card">
                <div class="card-title">Overall Codebase Health</div>
                <div class="card-value grade-{grade.lower()}">{score:.1f} <span style="font-size:1.25rem;">/ 100 ({grade})</span></div>
                <div class="card-sub">Architecture: {arch_score:.1f} | Security: {sec_score:.1f}</div>
            </div>
            <div class="card">
                <div class="card-title">Total Defects Flagged</div>
                <div class="card-value">{len(all_findings)}</div>
                <div class="card-sub">Security: {sec.total} | Architecture: {arch.total_findings}</div>
            </div>
            <div class="card">
                <div class="card-title">Critical & High Vulnerabilities</div>
                <div class="card-value" style="color:#ef4444;">{sec.critical + sec.high}</div>
                <div class="card-sub">Critical: {sec.critical} | High: {sec.high}</div>
            </div>
            <div class="card">
                <div class="card-title">Lines of Code Scanned</div>
                <div class="card-value">{total_loc:,}</div>
                <div class="card-sub">{total_files} files analyzed</div>
            </div>
        </section>

        <section>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2>Detected Findings ({len(all_findings)})</h2>
                <div class="filter-controls">
                    <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
                    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({sec.critical})</button>
                    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({sec.high})</button>
                    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({sec.medium})</button>
                    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({sec.low})</button>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 220px;">Rule ID</th>
                        <th style="width: 280px;">Location</th>
                        <th>Description & Remediation</th>
                    </tr>
                </thead>
                <tbody id="findings-body">
                    {''.join(rows_html) if rows_html else '<tr><td colspan="4" style="text-align:center; padding:3rem; color:#10b981;">✅ Clean scan! Zero defects detected.</td></tr>'}
                </tbody>
            </table>
        </section>
    </div>

    <script>
        function filterFindings(sev) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                if (sev === 'ALL' || row.getAttribute('data-sev') === sev) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
        return html_template
