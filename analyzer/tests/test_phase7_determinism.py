"""Unit tests verifying strict byte-level determinism of Phase 7 components, graphs, and health scores."""

from pathlib import Path
from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.reporting.json_reporter import JsonReporter


def test_phase7_repeated_analysis_identical_json():
    """Verify multiple pipeline runs on Phase 7 fixtures produce byte-identical JSON."""
    fixtures_to_test = [
        "component_cycle_project",
        "layered_inverted_project",
        "orphan_export_project",
        "sdp_violation_project",
    ]
    reporter = JsonReporter()
    pipeline = AnalysisPipeline()
    config = AnalysisConfig(output_format=OutputFormat.JSON)

    for fixture_name in fixtures_to_test:
        target_path = str(Path(__file__).resolve().parent / "fixtures" / "phase7" / fixture_name)
        
        run1 = pipeline.run(target_path, analysis_config=config)
        run2 = pipeline.run(target_path, analysis_config=config)

        # Normalize duration and timestamp metadata for exact byte comparison
        run2.id = run1.id
        run2.metadata.started_at = run1.metadata.started_at
        run2.metadata.completed_at = run1.metadata.completed_at
        run2.metadata.duration_seconds = run1.metadata.duration_seconds

        json1 = reporter.render(run1)
        json2 = reporter.render(run2)

        assert json1 == json2, f"Determinism failure in fixture {fixture_name}"

        # Ensure finding IDs match identically
        ids1 = [f.id for f in run1.architecture_findings]
        ids2 = [f.id for f in run2.architecture_findings]
        assert ids1 == ids2

        # Ensure component graph node IDs and edge IDs match identically
        assert run1.graph.component_graph is not None
        assert run2.graph.component_graph is not None
        cg_nodes_1 = [n.id for n in run1.graph.component_graph.nodes]
        cg_nodes_2 = [n.id for n in run2.graph.component_graph.nodes]
        assert cg_nodes_1 == cg_nodes_2

        # Ensure health scores match identically
        assert run1.health.overall_score == run2.health.overall_score
        assert run1.health.overall_grade == run2.health.overall_grade
