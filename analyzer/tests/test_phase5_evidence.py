"""Phase 5 tests for structured evidence across security and architecture rules."""

from analyzer.architecture.rules.arc_001_circular import RuleArc001
from analyzer.architecture.rules.arc_002_coupling import RuleArc002
from analyzer.architecture.rules.arc_003_god_module import RuleArc003
from analyzer.architecture.rules.arc_004_deep_chain import RuleArc004
from analyzer.models.graph import ArchitectureGraph, CircularDependency, DependencyEdge, DependencyNode
from analyzer.security.javascript.sec_js_004_client_secrets import RuleSecJs004
from analyzer.security.python.sec_py_001_secrets import RuleSecPy001
from analyzer.security.python.sec_py_003_subprocess import RuleSecPy003


def test_sec_py_001_structured_evidence_and_redaction():
    rule = RuleSecPy001()
    secret = "AKIAIOSFODNN7EXAMPLE12"
    code = f'aws_secret_access_key = "{secret}"'
    findings = rule.analyze("config.py", code)

    assert len(findings) == 1
    f = findings[0]
    assert "variable_name" in f.evidence
    assert f.evidence["variable_name"] == "aws_secret_access_key"
    assert "entropy" in f.evidence
    assert "secret_preview" in f.evidence
    # Ensure full secret is NOT in evidence or code_snippet
    assert secret not in f.evidence["secret_preview"]
    assert secret not in f.code_snippet
    assert "..." in f.evidence["secret_preview"]
    assert "..." in f.code_snippet


def test_sec_py_003_structured_evidence():
    rule = RuleSecPy003()
    code = "import subprocess\nsubprocess.run(f'cat {user_input}', shell=True)"
    findings = rule.analyze("handler.py", code)

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["pattern"] == "shell=True"
    assert "subprocess" in f.evidence["function"]
    assert f.evidence["dynamic_argument"] is True


def test_sec_js_004_structured_evidence_and_redaction():
    rule = RuleSecJs004()
    secret = "custom_mock_secret_token_1234567890_abcdef"
    code = f'const client_secret = "{secret}";'
    findings = rule.analyze("api.ts", code)

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["variable_name"] == "client_secret"
    assert "entropy" in f.evidence
    assert "secret_preview" in f.evidence
    assert secret not in f.evidence["secret_preview"]
    assert secret not in f.code_snippet


def test_arc_001_structured_evidence():
    rule = RuleArc001()
    cycle = CircularDependency(
        cycle_id="cycle-1",
        length=2,
        modules=["app.py", "utils.py"],
    )
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="app.py", file_path="app.py", module_name="app", language="python", loc=50),
            DependencyNode(id="utils.py", file_path="utils.py", module_name="utils", language="python", loc=50),
        ],
        edges=[
            DependencyEdge(source="app.py", target="utils.py", line_number=2),
            DependencyEdge(source="utils.py", target="app.py", line_number=5),
        ],
        circular_dependencies=[cycle],
    )
    findings = rule.analyze(graph)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["cycle"] == ["app.py", "utils.py"]
    assert f.evidence["cycle_length"] == 2
    assert "app.py -> utils.py -> app.py" in f.evidence["cycle_path"]


def test_arc_002_structured_evidence():
    rule = RuleArc002(threshold=3)
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(id="hub.py", file_path="hub.py", module_name="hub", language="python", fan_out=5, loc=100),
        ],
        edges=[],
    )
    findings = rule.analyze(graph)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["module"] == "hub"
    assert f.evidence["fan_out"] == 5
    assert f.evidence["threshold"] == 3


def test_arc_003_structured_evidence_and_heuristic_disclaimer():
    rule = RuleArc003(loc_threshold_1=100, fan_out_threshold_1=4, fan_in_threshold_1=2)
    graph = ArchitectureGraph(
        nodes=[
            DependencyNode(
                id="big.py",
                file_path="big.py",
                module_name="big",
                language="python",
                loc=200,
                fan_out=6,
                fan_in=4,
            ),
        ],
        edges=[],
    )
    findings = rule.analyze(graph)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["module"] == "big"
    assert f.evidence["loc"] == 200
    assert f.evidence["fan_out"] == 6
    assert f.evidence["fan_in"] == 4
    assert "thresholds" in f.evidence
    assert "matched_condition" in f.evidence
    # Explicit heuristic verification: never claim semantic proof
    assert "heuristic" in f.explanation.lower()


def test_arc_004_structured_evidence():
    rule = RuleArc004(depth_threshold=2)
    # Chain: m1 -> m2 -> m3 -> m4 (depth = 3 > 2)
    nodes = [DependencyNode(id=f"m{i}.py", file_path=f"m{i}.py", module_name=f"m{i}", language="python", loc=20) for i in range(1, 5)]
    edges = [
        DependencyEdge(source="m1.py", target="m2.py"),
        DependencyEdge(source="m2.py", target="m3.py"),
        DependencyEdge(source="m3.py", target="m4.py"),
    ]
    graph = ArchitectureGraph(nodes=nodes, edges=edges)
    findings = rule.analyze(graph)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["depth"] == 3
    assert f.evidence["threshold"] == 2
    assert len(f.evidence["longest_path"]) == 4
    assert "m1.py -> m2.py -> m3.py -> m4.py" in f.evidence["chain"]
