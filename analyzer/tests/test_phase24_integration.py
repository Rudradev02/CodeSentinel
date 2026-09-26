"""Integration tests for Phase 24 Policy-Aware Security Verification, Proof Obligations, and SARIF Diagnostics."""

import json
from pathlib import Path
import pytest
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.reporting.sarif import SarifReporter


def test_phase24_pipeline_security_evidence_chain_and_obligations(tmp_path: Path):
    """Verify AnalysisPipeline generates findings with proof obligations and rich evidence chain."""
    app_py = tmp_path / "app.py"
    app_py.write_text(
        """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return "ok"
""",
        encoding="utf-8",
    )

    cfg = AnalysisConfig(
        enable_policy_engine=True,
        enable_proof_obligations=True,
        policy_mode="ADVISORY",
    )
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=cfg)

    sec_findings = [f for f in result.security_findings if f.rule_id == "SEC-PY-001"]
    assert len(sec_findings) > 0
    f = sec_findings[0]

    assert f.evidence is not None
    assert "policy_evaluation" in f.evidence
    pol_eval = f.evidence["policy_evaluation"]
    assert pol_eval["policy_id"] == "POL-SQL-01"

    assert "proof_obligations" in f.evidence
    obligations = f.evidence["proof_obligations"]
    assert len(obligations) > 0
    kinds = [o["kind"] for o in obligations]
    assert "REQUIRES_PROPERTY" in kinds or "REQUIRES_AUTHENTICATION" in kinds


def test_phase24_sarif_surfaces_proof_obligations(tmp_path: Path):
    """Verify SARIF report surfaces proofObligations and unknownReasons in property bags."""
    app_py = tmp_path / "server.py"
    app_py.write_text(
        """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q")
    conn = sqlite3.connect("data.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE name = '" + q + "'")
    return "done"
""",
        encoding="utf-8",
    )

    cfg = AnalysisConfig(enable_proof_obligations=True, policy_mode="ADVISORY")
    pipeline = AnalysisPipeline()
    result = pipeline.run(target_path=tmp_path, analysis_config=cfg)

    reporter = SarifReporter()
    sarif_str = reporter.render(result)
    sarif_json = json.loads(sarif_str)

    runs = sarif_json.get("runs", [])
    assert len(runs) > 0
    results = runs[0].get("results", [])
    sql_results = [r for r in results if r.get("ruleId") == "SEC-PY-001"]
    assert len(sql_results) > 0

    sql_res = sql_results[0]
    props = sql_res.get("properties", {})
    assert "policyId" in props
    assert "proofObligations" in props
    assert isinstance(props["proofObligations"], list)
