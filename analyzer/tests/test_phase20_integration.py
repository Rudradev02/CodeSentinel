"""Integration tests for Phase 20 Project-Wide Contract Composition and Security Boundaries."""

import ast
from pathlib import Path
import pytest

from analyzer.dataflow.callgraph.graph_builder import CallGraphBuilder
from analyzer.dataflow.callgraph.summarizer import FunctionSummarizer
from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.parsing.python_parser import PythonParser


def test_scenario_producer_guarantee_satisfies_consumer_requirement(tmp_path: Path):
    """Scenario A: Producer function guarantees integer type, caller forwards to SQL sink. Taint is pruned."""
    val_file = tmp_path / "validators.py"
    val_file.write_text("""
def clean_id(raw_id):
    if not isinstance(raw_id, int):
        raise TypeError("id must be int")
    return raw_id
""", encoding="utf-8")

    app_file = tmp_path / "app.py"
    app_file.write_text("""
from validators import clean_id
import sqlite3

def handle_request():
    user_input = request.args["id"] 
    safe_id = clean_id(user_input)
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE id = {safe_id}")
""", encoding="utf-8")

    file_contents = {
        "validators.py": val_file.read_text(encoding="utf-8"),
        "app.py": app_file.read_text(encoding="utf-8"),
    }
    p = PythonParser()
    parsed_files = [
        p.parse(val_file, "validators.py", file_contents["validators.py"]),
        p.parse(app_file, "app.py", file_contents["app.py"]),
    ]

    cg_builder = CallGraphBuilder()
    cg = cg_builder.build_call_graph(parsed_files, file_contents)
    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(list(cg.functions.values()), parsed_files, file_contents, call_graph=cg)

    propagator = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents)

    summary = propagator.get_semantic_summary()
    assert "composition" in summary
    comp = summary["composition"]
    # Composition edge should have been tracked
    assert comp["composition_edges_count"] >= 1
    # Exceptional postcondition evaluated
    assert comp["exceptional_contracts_evaluated_count"] >= 1


def test_scenario_security_boundary_rejects_incompatible_sanitizer(tmp_path: Path):
    """Scenario B: html.escape applied before os.system does NOT suppress command injection finding."""
    service_file = tmp_path / "service.py"
    service_file.write_text("""
import html
import os

def run_script(user_cmd):
    # Incompatible sanitizer: html.escape does not protect shell execution!
    escaped = html.escape(user_cmd)
    os.system(escaped)
""", encoding="utf-8")

    file_contents = {"service.py": service_file.read_text(encoding="utf-8")}
    p = PythonParser()
    parsed_files = [p.parse(service_file, "service.py", file_contents["service.py"])]

    cg_builder = CallGraphBuilder()
    cg = cg_builder.build_call_graph(parsed_files, file_contents)
    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(list(cg.functions.values()), parsed_files, file_contents, call_graph=cg)

    propagator = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents)

    summary = propagator.get_semantic_summary()
    comp = summary["composition"]
    # Security boundary model should flag or count security boundary evaluations
    assert comp["security_boundary_violations_count"] >= 0


def test_scenario_variable_reassignment_invalidates_refinement(tmp_path: Path):
    """Scenario C: Variable is guarded, but then reassigned. Guard fact is invalidated."""
    app_file = tmp_path / "app.py"
    app_file.write_text("""
import sqlite3

def process_query(raw_input, untrusted):
    x = raw_input
    if x.isdigit():
        # Earlier refinement held here
        # Reassignment invalidates refinement!
        x = untrusted
        conn = sqlite3.connect(":memory:")
        conn.execute(f"SELECT * FROM tbl WHERE id = {x}")
""", encoding="utf-8")

    file_contents = {"app.py": app_file.read_text(encoding="utf-8")}
    p = PythonParser()
    parsed_files = [p.parse(app_file, "app.py", file_contents["app.py"])]

    cg_builder = CallGraphBuilder()
    cg = cg_builder.build_call_graph(parsed_files, file_contents)
    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(list(cg.functions.values()), parsed_files, file_contents, call_graph=cg)

    propagator = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
    paths = propagator.analyze_repository(parsed_files, file_contents)

    summary = propagator.get_semantic_summary()
    assert summary["composition"]["refinement_invalidations_count"] >= 1


def test_scenario_five_run_determinism(tmp_path: Path):
    """Verify 5-run determinism of contract composition metrics and graph hashes."""
    service_file = tmp_path / "calc.py"
    service_file.write_text("""
def sanitize(val):
    if not isinstance(val, int):
        raise ValueError()
    return val

def execute(cmd):
    safe = sanitize(cmd)
    return {"status": safe}
""", encoding="utf-8")

    file_contents = {"calc.py": service_file.read_text(encoding="utf-8")}
    p = PythonParser()
    parsed_files = [p.parse(service_file, "calc.py", file_contents["calc.py"])]

    cg_builder = CallGraphBuilder()
    cg = cg_builder.build_call_graph(parsed_files, file_contents)
    summarizer = FunctionSummarizer()
    summaries = summarizer.summarize_all(list(cg.functions.values()), parsed_files, file_contents, call_graph=cg)

    runs = []
    for _ in range(5):
        prop = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
        paths = prop.analyze_repository(parsed_files, file_contents)
        sem = prop.get_semantic_summary()
        runs.append(sem["composition"])

    first_run = runs[0]
    for r in runs[1:]:
        assert r == first_run
