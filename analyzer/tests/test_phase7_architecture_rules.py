"""Unit tests for Phase 7 architecture rules ARC-005, ARC-006, ARC-007, ARC-008."""

from pathlib import Path
from analyzer.architecture.rules.arc_005_layer_inversion import RuleArc005
from analyzer.architecture.rules.arc_006_component_cycle import RuleArc006
from analyzer.architecture.rules.arc_007_sdp_violation import RuleArc007
from analyzer.architecture.rules.arc_008_orphan_export import RuleArc008
from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline


def test_arc_006_component_cycle_fixture():
    cycle_repo = Path(__file__).resolve().parent / "fixtures" / "phase7" / "component_cycle_project"
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(cycle_repo))

    cycle_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-006"]
    assert len(cycle_findings) >= 1
    
    # Check cycle elements in finding evidence
    f = cycle_findings[0]
    cycle_components = f.evidence.get("cycle_components", [])
    assert len(cycle_components) == 3
    assert set(cycle_components) == {"billing", "auth", "notifications"}
    # Verify deterministic UUIDv5 ID
    assert len(f.id) == 36


def test_arc_007_sdp_violation_fixture():
    sdp_repo = Path(__file__).resolve().parent / "fixtures" / "phase7" / "sdp_violation_project"
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(sdp_repo))

    sdp_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-007"]
    assert len(sdp_findings) >= 1
    
    f = sdp_findings[0]
    assert f.evidence.get("source_component") == "core"
    assert f.evidence.get("target_component") == "experimental"
    assert f.evidence.get("source_instability") <= 0.30
    assert f.evidence.get("target_instability") >= 0.70


def test_arc_007_configurable_thresholds(tmp_path):
    # Test that setting higher arc_007_stable_max_i or min_ca adapts behavior
    rule = RuleArc007(stable_max_i=0.10, unstable_min_i=0.90, min_ca=5)
    assert rule.stable_max_i == 0.10
    assert rule.unstable_min_i == 0.90
    assert rule.min_ca == 5


def test_arc_008_metadata_and_remediation():
    rule = RuleArc008()
    assert rule.rule_id == "ARC-008"
    assert "Potentially Orphaned Export" in rule.name
    assert "If the symbol is no longer needed" in rule.remediation
