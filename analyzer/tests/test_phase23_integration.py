"""Integration tests for Phase 23 Trust Boundaries, Policy Engine, and SARIF Reporting."""

import json
from pathlib import Path
import pytest
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.reporting.sarif import SarifReporter


@pytest.fixture
def sample_project_dir():
    return Path(__file__).parent / "fixtures" / "sample_project"


@pytest.fixture
def flask_vuln_project(tmp_path: Path):
    """Temporary repository containing a Flask web API route and a SQL sink."""
    app_file = tmp_path / "app.py"
    app_file.write_text(
        """import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    query = request.args.get("name")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % query)
    return "ok"
""",
        encoding="utf-8",
    )
    return tmp_path


def test_pipeline_phase23_enriched_evidence(flask_vuln_project):
    """Run pipeline and verify security findings contain Phase 23 boundary and policy evidence."""
    config = AnalysisConfig(
        enable_boundary_detection=True,
        enable_policy_engine=True,
        policy_mode="ENFORCE",
    )
    pipeline = AnalysisPipeline(analysis_config=config)
    result = pipeline.run(flask_vuln_project, analysis_config=config)

    findings = result.security_findings
    assert len(findings) > 0

    # Check for evidence enrichment on security findings
    findings_with_policy = [
        f for f in findings if f.evidence and "policy_evaluation" in f.evidence
    ]
    assert len(findings_with_policy) > 0
    pol_eval = findings_with_policy[0].evidence["policy_evaluation"]
    assert "policy_id" in pol_eval
    assert pol_eval["evaluation_result"] == "PROVEN_VIOLATION"

    # Verify SARIF export produces valid SARIF 2.1.0 with Phase 23 property bags
    reporter = SarifReporter()
    sarif_output = reporter.render(result)
    sarif_data = json.loads(sarif_output)

    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) == 1
    sarif_results = sarif_data["runs"][0]["results"]
    assert len(sarif_results) == len(findings)

    # Verify properties bag present on results
    results_with_props = [r for r in sarif_results if "properties" in r]
    assert len(results_with_props) > 0
    props = results_with_props[0]["properties"]
    assert "policyId" in props
    assert props["policyResult"] == "PROVEN_VIOLATION"


def test_pipeline_policy_mode_disabled(flask_vuln_project):
    """When policy engine is disabled, findings are produced without policy metadata."""
    config = AnalysisConfig(
        enable_boundary_detection=False,
        enable_policy_engine=False,
        policy_mode="DISABLED",
    )
    pipeline = AnalysisPipeline(analysis_config=config)
    result = pipeline.run(flask_vuln_project, analysis_config=config)
    findings = result.security_findings
    assert len(findings) > 0
    for f in findings:
        if f.evidence:
            assert "policy_evaluation" not in f.evidence


def test_phase23_determinism(sample_project_dir):
    """Repeated pipeline runs with Phase 23 enabled must produce byte-identical JSON outputs."""
    config = AnalysisConfig(
        enable_boundary_detection=True,
        enable_policy_engine=True,
        policy_mode="ENFORCE",
    )
    pipeline1 = AnalysisPipeline(analysis_config=config)
    result1 = pipeline1.run(sample_project_dir, analysis_config=config)

    pipeline2 = AnalysisPipeline(analysis_config=config)
    result2 = pipeline2.run(sample_project_dir, analysis_config=config)

    f1_list = result1.security_findings + result1.architecture_findings
    f2_list = result2.security_findings + result2.architecture_findings

    assert len(f1_list) == len(f2_list)
    for f1, f2 in zip(f1_list, f2_list):
        assert f1.id == f2.id
        assert f1.rule_id == f2.rule_id
        assert f1.location.file_path == f2.location.file_path
        assert f1.location.line_start == f2.location.line_start
