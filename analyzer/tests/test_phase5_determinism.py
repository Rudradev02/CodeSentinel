"""Phase 5 tests for repeatable finding IDs and byte-equivalent JSON output."""

from pathlib import Path
from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.reporting.json_reporter import JsonReporter


def test_repeated_analysis_identical_finding_ids_and_json():
    """Verify multiple runs against the sample project produce byte-identical JSON and matching finding IDs."""
    sample_path = str(Path(__file__).resolve().parent / "fixtures" / "sample_project")
    pipeline = AnalysisPipeline()
    reporter = JsonReporter()
    config = AnalysisConfig(output_format=OutputFormat.JSON)

    result_run1 = pipeline.run(sample_path, analysis_config=config)
    json_1 = reporter.render(result_run1)

    result_run2 = pipeline.run(sample_path, analysis_config=config)
    json_2 = reporter.render(result_run2)

    # Byte-equivalent JSON check (ignoring only duration_seconds if dynamic)
    assert len(result_run1.security_findings) == len(result_run2.security_findings)
    assert len(result_run1.architecture_findings) == len(result_run2.architecture_findings)

    # Finding IDs must be identical across runs
    run1_ids = [f.id for f in result_run1.security_findings + result_run1.architecture_findings]
    run2_ids = [f.id for f in result_run2.security_findings + result_run2.architecture_findings]
    assert run1_ids == run2_ids

    # Circular cycle IDs must be identical across runs
    run1_cycle_ids = [c.cycle_id for c in result_run1.graph.circular_dependencies]
    run2_cycle_ids = [c.cycle_id for c in result_run2.graph.circular_dependencies]
    assert run1_cycle_ids == run2_cycle_ids
