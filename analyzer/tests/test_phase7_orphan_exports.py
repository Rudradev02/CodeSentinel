"""Unit tests for OrphanExportAnalyzer and conservative dead-export detection."""

from pathlib import Path
from analyzer.architecture.orphan_exports import OrphanExportAnalyzer
from analyzer.engine.pipeline import AnalysisPipeline


def test_orphan_export_on_fixture():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "phase7" / "orphan_export_project"
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(fixture_path))

    orphan_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-008"]
    # We exported calculate_tax, unused_formula, and UnusedRecord.
    # calculate_tax is imported by services/calculator.py, so only unused_formula and UnusedRecord should be flagged.
    flagged_symbols = {f.evidence.get("symbol") for f in orphan_findings}
    assert "unused_formula" in flagged_symbols
    assert "UnusedRecord" in flagged_symbols
    assert "calculate_tax" not in flagged_symbols


def test_entry_point_files_ignored(tmp_path):
    # If file is main.py or setup.py or index.ts, exports should not be flagged as orphaned
    main_file = tmp_path / "main.py"
    main_file.write_text("def cli_entry():\n    pass\n", encoding="utf-8")
    
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(tmp_path))
    orphan_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-008"]
    assert len(orphan_findings) == 0


def test_whole_module_import_suppression(tmp_path):
    # If module A is imported as a whole (e.g. import pkg.module_a), its exports should not be flagged
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "helpers.py").write_text("def foo():\n    return 1\ndef bar():\n    return 2\n", encoding="utf-8")
    (pkg / "consumer.py").write_text("import pkg.helpers\n\nx = pkg.helpers.foo()\n", encoding="utf-8")

    pipeline = AnalysisPipeline()
    result = pipeline.run(str(tmp_path))
    orphan_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-008"]
    # foo and bar should not be flagged because pkg.helpers was whole-module imported
    symbols = {f.evidence.get("symbol") for f in orphan_findings}
    assert "foo" not in symbols
    assert "bar" not in symbols
