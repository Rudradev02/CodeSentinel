"""Unit tests for Phase 21 reverse dependency and impact analysis."""

from analyzer.dataflow.callgraph.models import FunctionDefinition, ParameterDef
from analyzer.incremental.impact import (
    build_impact_set,
    classify_function_change,
    compute_reverse_dependency_closure,
)
from analyzer.incremental.models import FunctionChangeKind, InvalidationReason


class TestReverseDependencyClosure:
    """Verifies graph inversion and transitive impact calculations."""

    def test_linear_dependency_chain(self):
        # A imports B, B imports C, C imports D
        # graph maps importer -> {imported}
        dep_graph = {
            "A.py": {"B.py"},
            "B.py": {"C.py"},
            "C.py": {"D.py"},
            "D.py": set(),
            "X.py": {"Y.py"},
            "Y.py": set(),
        }

        # Modify D.py -> affected must be D, C, B, A
        affected = compute_reverse_dependency_closure({"D.py"}, dep_graph)
        assert affected == {"D.py", "C.py", "B.py", "A.py"}
        # Unrelated files must NOT be affected
        assert "X.py" not in affected
        assert "Y.py" not in affected

    def test_cycle_and_diamond_graph(self):
        # A imports B and C, both import D
        # D also imports B (cycle)
        dep_graph = {
            "A.py": {"B.py", "C.py"},
            "B.py": {"D.py"},
            "C.py": {"D.py"},
            "D.py": {"B.py"},
        }

        affected = compute_reverse_dependency_closure({"D.py"}, dep_graph)
        assert affected == {"D.py", "B.py", "C.py", "A.py"}


class TestFunctionChangeClassification:
    """Verifies classification of function body-only vs signature modifications."""

    def test_signature_changed_parameter_count(self):
        f1 = FunctionDefinition(
            id="f1",
            qualified_name="pkg.service",
            file_path="pkg/service.py",
            language="PYTHON",
            name="service",
            line_start=1,
            line_end=10,
            parameters=[ParameterDef(name="x", position=0)],
        )
        f2 = FunctionDefinition(
            id="f1",
            qualified_name="pkg.service",
            file_path="pkg/service.py",
            language="PYTHON",
            name="service",
            line_start=1,
            line_end=12,
            parameters=[ParameterDef(name="x", position=0), ParameterDef(name="y", position=1)],
        )
        kind = classify_function_change(f1, f2)
        assert kind == FunctionChangeKind.SIGNATURE_CHANGED

    def test_body_changed_only(self):
        f1 = FunctionDefinition(
            id="f1",
            qualified_name="pkg.calc",
            file_path="pkg/calc.py",
            language="PYTHON",
            name="calc",
            line_start=1,
            line_end=5,
            parameters=[ParameterDef(name="x", position=0)],
        )
        f2 = FunctionDefinition(
            id="f1",
            qualified_name="pkg.calc",
            file_path="pkg/calc.py",
            language="PYTHON",
            name="calc",
            line_start=1,
            line_end=6,
            parameters=[ParameterDef(name="x", position=0)],
        )
        kind = classify_function_change(f1, f2, old_body_hash="hash_a", new_body_hash="hash_b")
        assert kind == FunctionChangeKind.BODY_CHANGED_ONLY


class TestBuildImpactSet:
    """Verifies construction of the full ImpactSet."""

    def test_impact_set_reasons_and_reusable(self):
        dep_graph = {
            "app/controller.py": {"app/service.py"},
            "app/service.py": {"app/repo.py"},
            "app/repo.py": set(),
            "utils/helpers.py": set(),
        }
        all_files = {"app/controller.py", "app/service.py", "app/repo.py", "utils/helpers.py"}

        impact = build_impact_set(
            directly_changed={"app/repo.py"},
            added_files=set(),
            deleted_files=set(),
            renamed_files={},
            all_discovered_files=all_files,
            dependency_graph=dep_graph,
        )

        assert impact.directly_changed_files == {"app/repo.py"}
        assert impact.affected_files == {"app/repo.py", "app/service.py", "app/controller.py"}
        assert impact.reusable_files == {"utils/helpers.py"}
        assert impact.invalidation_reasons["app/repo.py"] == InvalidationReason.DIRECT_SOURCE_CHANGE
        assert impact.invalidation_reasons["app/service.py"] == InvalidationReason.DEPENDENCY_CHANGE

    def test_unresolved_dependency_conservative_component_invalidation(self):
        dep_graph = {
            "auth/login.py": set(),
            "auth/register.py": set(),
            "billing/pay.py": set(),
        }
        all_files = {"auth/login.py", "auth/register.py", "billing/pay.py"}

        # auth/login.py has an unresolved dynamic import
        impact = build_impact_set(
            directly_changed={"auth/login.py"},
            added_files=set(),
            deleted_files=set(),
            renamed_files={},
            all_discovered_files=all_files,
            dependency_graph=dep_graph,
            has_unresolved_dependencies={"auth/login.py": True},
        )

        # auth/register.py in the same component directory must be conservatively invalidated
        assert "auth/register.py" in impact.affected_files
        assert "billing/pay.py" in impact.reusable_files
