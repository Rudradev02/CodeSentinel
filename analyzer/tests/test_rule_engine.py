"""Tests for RuleRegistry, RuleEngine orchestration, and deterministic repeated execution."""

import json
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.graph import (
    ArchitectureGraph,
    CircularDependency,
    CouplingMetrics,
    DependencyEdge,
    DependencyNode,
)
from analyzer.rules.engine import RuleEngine
from analyzer.rules.registry import RuleRegistry


def test_rule_registry_defaults():
    registry = RuleRegistry(load_defaults=True)
    defs = registry.get_rule_definitions()
    # 8 Python + 6 JS + 4 Arch = 18 rules
    assert len(defs) == 18

    # Verify lookup by ID
    assert registry.get_security_rule("SEC-PY-001") is not None
    assert registry.get_security_rule("SEC-JS-001") is not None
    assert registry.get_architecture_rule("ARC-001") is not None


def test_rule_registry_applicability_filtering():
    registry = RuleRegistry(load_defaults=True)

    # 1. Python with Django framework
    py_django_rules = registry.get_applicable_security_rules(
        language="PYTHON",
        detected_frameworks=["django"],
    )
    rule_ids = {r.rule_id for r in py_django_rules}
    assert "SEC-PY-001" in rule_ids  # general
    assert "SEC-PY-008" in rule_ids  # django
    assert "SEC-JS-001" not in rule_ids  # JS rule excluded

    # 2. Python without Django/Flask (only general)
    py_general_rules = registry.get_applicable_security_rules(
        language="PYTHON",
        detected_frameworks=[],
    )
    general_rule_ids = {r.rule_id for r in py_general_rules}
    assert "SEC-PY-001" in general_rule_ids
    # Django-only rule SEC-PY-008 should NOT be present if framework not detected
    assert "SEC-PY-008" not in general_rule_ids

    # 3. JavaScript with React
    js_react_rules = registry.get_applicable_security_rules(
        language="JAVASCRIPT",
        detected_frameworks=["react"],
    )
    js_rule_ids = {r.rule_id for r in js_react_rules}
    assert "SEC-JS-001" in js_rule_ids
    assert "SEC-JS-003" in js_rule_ids
    assert "SEC-PY-001" not in js_rule_ids


def test_rule_engine_deterministic_repeated_execution():
    """Verify that running the RuleEngine twice on identical inputs produces identical findings and JSON."""
    engine = RuleEngine()

    files = [
        DiscoveredFileMetadata(
            path="/repo/auth.py",
            relative_path="auth.py",
            extension=".py",
            language="PYTHON",
            size_bytes=100,
            line_count=5,
        ),
        DiscoveredFileMetadata(
            path="/repo/client.js",
            relative_path="client.js",
            extension=".js",
            language="JAVASCRIPT",
            size_bytes=100,
            line_count=5,
        ),
    ]

    file_contents = {
        "auth.py": 'SECRET_KEY = "django-insecure-x%89234jklnsdf@#$234"\nDEBUG = True\nresult = eval(payload)',
        "client.js": 'const res = eval(payload);\nconst clientSecret = "custom_mock_secret_token_1234567890_abcdef";',
    }

    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="a.py", file_path="a.py", module_name="a", language="PYTHON"),
            DependencyNode(id="b.py", file_path="b.py", module_name="b", language="PYTHON"),
        ],
        edges=[
            DependencyEdge(source="a.py", target="b.py", is_circular=True, line_number=1),
            DependencyEdge(source="b.py", target="a.py", is_circular=True, line_number=1),
        ],
        circular_dependencies=[CircularDependency(modules=["a.py", "b.py"], length=2)],
        metrics=CouplingMetrics(total_modules=2, total_edges=2, circular_cycles_count=1),
    )

    # Execution 1
    sec_findings_1, sec_sum_1 = engine.analyze_security(
        files=files,
        file_contents=file_contents,
        parsed_files=[],
        detected_frameworks=["django"],
    )
    arch_findings_1, arch_sum_1 = engine.analyze_architecture(graph)

    # Execution 2
    sec_findings_2, sec_sum_2 = engine.analyze_security(
        files=files,
        file_contents=file_contents,
        parsed_files=[],
        detected_frameworks=["django"],
    )
    arch_findings_2, arch_sum_2 = engine.analyze_architecture(graph)

    # 1. Assert exact equality of finding models
    assert sec_findings_1 == sec_findings_2
    assert arch_findings_1 == arch_findings_2
    assert sec_sum_1 == sec_sum_2
    assert arch_sum_1 == arch_sum_2

    # 2. Assert exact equality of deterministic IDs
    ids_1 = [f.id for f in sec_findings_1]
    ids_2 = [f.id for f in sec_findings_2]
    assert ids_1 == ids_2

    # 3. Assert deterministic ordering
    sorted_tuples = [
        (f.location.file_path, f.location.line_start, f.location.col_start or 0, f.rule_id)
        for f in sec_findings_1
    ]
    assert sorted_tuples == sorted(sorted_tuples)

    # 4. Assert byte-for-byte JSON serialization equality
    json_1 = json.dumps([f.model_dump(mode="json") for f in sec_findings_1], sort_keys=True)
    json_2 = json.dumps([f.model_dump(mode="json") for f in sec_findings_2], sort_keys=True)
    assert json_1 == json_2
