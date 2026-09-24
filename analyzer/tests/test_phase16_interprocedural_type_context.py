"""Comprehensive unit and scenario tests for Phase 16 Type-Aware & Context-Sensitive Propagation."""

import ast
import pytest
from analyzer.dataflow.callgraph.models import (
    CallGraph,
    FunctionDefinition,
    FunctionSummary,
    ParameterDef,
    SummarySinkInvocation,
    TaintTransfer,
)
from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator
from analyzer.dataflow.taint.models import SinkCategory


@pytest.fixture
def repo_callgraph():
    # 1. Caller: handle_request in app/views.py
    f_caller = FunctionDefinition(
        id="fn-view-req",
        qualified_name="app.views.handle_request",
        file_path="app/views.py",
        language="PYTHON",
        name="handle_request",
        line_start=1,
        line_end=10,
    )
    # 2. UserRepository.find_by_id in app/repo.py
    f_repo = FunctionDefinition(
        id="fn-repo-find",
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        language="PYTHON",
        name="find_by_id",
        line_start=1,
        line_end=10,
        is_method=True,
        class_name="UserRepository",
        module_path="app.repo",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
    )
    # 3. DatabaseClient.execute in app/db.py
    f_db = FunctionDefinition(
        id="fn-db-exec",
        qualified_name="app.db.DatabaseClient.execute",
        file_path="app/db.py",
        language="PYTHON",
        name="execute",
        line_start=1,
        line_end=10,
        is_method=True,
        class_name="DatabaseClient",
        module_path="app.db",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="query", position=1)],
    )

    cg = CallGraph()
    cg.functions[f_caller.qualified_name] = f_caller
    cg.functions[f_repo.qualified_name] = f_repo
    cg.functions[f_db.qualified_name] = f_db
    return cg


def test_scenario_a_known_receiver_dispatch(repo_callgraph):
    # UserRepository.find_by_id internally executes an SQL query sink
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}

    view_code = """def handle_request():
    uid = request.args['id']
    repo = UserRepository()
    repo.find_by_id(uid)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    assert len(paths) >= 1
    p = paths[0]
    assert p.category == SinkCategory.SQL_EXECUTE
    assert len(p.call_chain) == 1
    step = p.call_chain[0]
    assert step.callee_function == "app.repo.UserRepository.find_by_id"
    assert step.receiver_type == "app.repo.UserRepository"
    assert step.receiver_confidence == "KNOWN"
    assert step.context_id != "ROOT"


def test_scenario_d_contextual_sanitizer_separation(repo_callgraph):
    # clean_or_raw transfers taint to return
    summary_clean = FunctionSummary(
        qualified_name="app.utils.clean_or_raw",
        file_path="app/utils.py",
        parameters=[ParameterDef(name="m", position=0), ParameterDef(name="sanitize", position=1)],
        taint_transfers=[
            TaintTransfer(from_param_index=0, to_return=True)
        ],
    )
    summaries = {summary_clean.qualified_name: summary_clean}

    # In view_code, we use clean_or_raw with safe context and vulnerable context
    view_code = """def handle_request():
    # Context 1: Safe constant
    safe_data = "hello"
    clean_or_raw(safe_data, sanitize=True)

    # Context 2: Vulnerable input
    user_input = request.args['q']
    raw = clean_or_raw(user_input, sanitize=False)
    cursor.execute(f"SELECT * FROM items WHERE name = '{raw}'")
"""
    # Register function clean_or_raw in callgraph
    f_clean = FunctionDefinition(
        id="fn-clean-or-raw",
        qualified_name="app.utils.clean_or_raw",
        file_path="app/utils.py",
        language="PYTHON",
        name="clean_or_raw",
        line_start=1,
        line_end=5,
        parameters=[ParameterDef(name="m", position=0), ParameterDef(name="sanitize", position=1)],
    )
    repo_callgraph.functions[f_clean.qualified_name] = f_clean

    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )

    assert len(paths) >= 1
    p = paths[0]
    assert p.category == SinkCategory.SQL_EXECUTE
    assert p.call_chain[0].taint_action == "PROPAGATE_THROUGH"


def test_scenario_i_disable_type_inference_fallback(repo_callgraph):
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}

    view_code = """
def handle_request():
    uid = request.args.get("id")
    repo = UserRepository()
    repo.find_by_id(uid)
"""
    # When type inference is disabled, repo.find_by_id cannot resolve receiver type
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
        disable_type_inference=True,
    )

    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )
    # Should fall back cleanly without throwing exceptions
    assert isinstance(paths, list)


def test_scenario_b_constructor_param_and_field_propagation(repo_callgraph):
    f_service_init = FunctionDefinition(
        id="fn-service-init",
        qualified_name="app.service.UserService.__init__",
        file_path="app/service.py",
        language="PYTHON",
        name="__init__",
        line_start=1,
        line_end=4,
        is_method=True,
        class_name="UserService",
        module_path="app.service",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="db", position=1, type_annotation="DatabaseClient")],
    )
    f_service_update = FunctionDefinition(
        id="fn-service-update",
        qualified_name="app.service.UserService.update_user",
        file_path="app/service.py",
        language="PYTHON",
        name="update_user",
        line_start=5,
        line_end=10,
        is_method=True,
        class_name="UserService",
        module_path="app.service",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1), ParameterDef(name="raw_bio", position=2)],
    )
    repo_callgraph.functions[f_service_init.qualified_name] = f_service_init
    repo_callgraph.functions[f_service_update.qualified_name] = f_service_update

    summary_update = FunctionSummary(
        qualified_name="app.service.UserService.update_user",
        file_path="app/service.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1), ParameterDef(name="raw_bio", position=2)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=2,
                line=8,
            )
        ],
    )
    summaries = {summary_update.qualified_name: summary_update}

    view_code = """def handle_request():
    bio = request.POST.get("bio")
    service = UserService(DatabaseClient())
    service.update_user(123, bio)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
    )
    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )
    assert len(paths) >= 1
    assert paths[0].category == SinkCategory.SQL_EXECUTE
    assert paths[0].call_chain[0].receiver_type == "app.service.UserService"
    assert paths[0].call_chain[0].receiver_confidence == "KNOWN"


def test_scenario_c_ambiguous_receiver():
    from analyzer.dataflow.callgraph.type_resolver import TypeAwareCallResolver
    from analyzer.dataflow.types.models import TypeEnvironment

    f1 = FunctionDefinition(id="1", qualified_name="app.repo.AuditRepo.save", file_path="app/audit.py", language="PYTHON", name="save", line_start=1, line_end=5, is_method=True, class_name="AuditRepo")
    f2 = FunctionDefinition(id="2", qualified_name="app.repo.UserRepo.save", file_path="app/user.py", language="PYTHON", name="save", line_start=1, line_end=5, is_method=True, class_name="UserRepo")
    caller_fn = FunctionDefinition(id="caller", qualified_name="app.main.run", file_path="app/main.py", language="PYTHON", name="run", line_start=1, line_end=15)

    resolver = TypeAwareCallResolver(functions=[f1, f2, caller_fn])
    tenv = TypeEnvironment(scope_name="caller")
    edge, _ = resolver.resolve_call(caller=caller_fn, callee_expr="repo.save", line=10, col=4, arg_count=1, type_env=tenv)
    assert edge is not None
    assert edge.receiver_confidence == "AMBIGUOUS"
    assert edge.candidate_targets == ["app.repo.AuditRepo.save", "app.repo.UserRepo.save"]


def test_scenario_e_same_helper_two_callers():
    cg = CallGraph()
    f_caller1 = FunctionDefinition(id="c1", qualified_name="app.caller1", file_path="app/c1.py", language="PYTHON", name="caller1", line_start=1, line_end=5)
    f_caller2 = FunctionDefinition(id="c2", qualified_name="app.caller2", file_path="app/c2.py", language="PYTHON", name="caller2", line_start=1, line_end=5)
    f_helper = FunctionDefinition(id="h", qualified_name="app.helper", file_path="app/h.py", language="PYTHON", name="helper", line_start=1, line_end=5, parameters=[ParameterDef(name="data", position=0)])
    cg.functions[f_caller1.qualified_name] = f_caller1
    cg.functions[f_caller2.qualified_name] = f_caller2
    cg.functions[f_helper.qualified_name] = f_helper

    summary_helper = FunctionSummary(
        qualified_name="app.helper",
        file_path="app/h.py",
        parameters=[ParameterDef(name="data", position=0)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=0,
                line=3,
            )
        ],
    )
    summaries = {summary_helper.qualified_name: summary_helper}

    code_c1 = "def caller1():\n    helper('safe_constant')\n"
    code_c2 = "def caller2():\n    data = request.args['input']\n    helper(data)\n"

    propagator = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/c1.py": code_c1, "app/c2.py": code_c2},
        ast_cache={"app/c1.py": ast.parse(code_c1), "app/c2.py": ast.parse(code_c2)},
    )
    assert len(paths) == 1
    assert paths[0].call_chain[0].caller_function == "app.caller2"


def test_scenario_f_mutual_recursion_cycle():
    # Mutual recursion A -> B -> A terminated cleanly without stack overflow
    cg = CallGraph()
    fa = FunctionDefinition(id="a", qualified_name="pkg.fn_a", file_path="pkg/a.py", language="PYTHON", name="fn_a", line_start=1, line_end=5)
    fb = FunctionDefinition(id="b", qualified_name="pkg.fn_b", file_path="pkg/b.py", language="PYTHON", name="fn_b", line_start=1, line_end=5)
    cg.functions[fa.qualified_name] = fa
    cg.functions[fb.qualified_name] = fb

    sum_a = FunctionSummary(qualified_name="pkg.fn_a", file_path="pkg/a.py", parameters=[ParameterDef(name="x", position=0)])
    sum_b = FunctionSummary(qualified_name="pkg.fn_b", file_path="pkg/b.py", parameters=[ParameterDef(name="y", position=0)])
    summaries = {sum_a.qualified_name: sum_a, sum_b.qualified_name: sum_b}

    code_a = "def fn_a(x):\n    fn_b(x)\n"
    code_b = "def fn_b(y):\n    fn_a(y)\n"

    propagator = InterproceduralTaintPropagator(call_graph=cg, summaries=summaries)
    # Must terminate cleanly
    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"pkg/a.py": code_a, "pkg/b.py": code_b},
        ast_cache={"pkg/a.py": ast.parse(code_a), "pkg/b.py": ast.parse(code_b)},
    )
    assert isinstance(paths, list)


def test_scenario_g_context_cap_widening():
    from analyzer.dataflow.callgraph.context_manager import ContextManager
    from analyzer.dataflow.types.models import CallContext
    cm = ContextManager(max_k=2, max_contexts_per_function=8)
    root = CallContext.create_root_context()
    for i in range(10):
        ctx, truncated = cm.get_or_create_context(
            callee_qn="pkg.handler",
            parent=root,
            call_site_id=f"site_{i}",
            arg_taints=[True],
        )
        if i >= 8:
            assert truncated is True
            assert "MAX_CONTEXTS_PER_FUNCTION" in cm.truncation_reasons
    assert cm.total_contexts_count == 8


def test_scenario_h_type_inference_step_cap():
    from analyzer.dataflow.types.python_type_extractor import PythonTypeExtractor
    extractor = PythonTypeExtractor(max_inference_steps=50)
    stmts = "\n".join(f"    x_{i} = UserRepo()" for i in range(100))
    code = f"def test_func():\n{stmts}\n"
    tree = ast.parse(code)
    func_node = tree.body[0]
    tenv = extractor.extract_function_types(func_node, "test.py")
    assert tenv.bindings.get("x_0") is not None
    assert tenv.bindings.get("x_99") is None


def test_scenario_j_context_sensitivity_disabled(repo_callgraph):
    summary_repo = FunctionSummary(
        qualified_name="app.repo.UserRepository.find_by_id",
        file_path="app/repo.py",
        parameters=[ParameterDef(name="self", position=0), ParameterDef(name="user_id", position=1)],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SQL_EXECUTE",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=1,
                line=5,
            )
        ],
    )
    summaries = {summary_repo.qualified_name: summary_repo}
    view_code = """def handle_request():
    uid = request.args['id']
    repo = UserRepository()
    repo.find_by_id(uid)
"""
    propagator = InterproceduralTaintPropagator(
        call_graph=repo_callgraph,
        summaries=summaries,
        disable_context_sensitivity=True,
    )
    paths = propagator.analyze_repository(
        parsed_files=[],
        file_contents={"app/views.py": view_code},
        ast_cache={"app/views.py": ast.parse(view_code)},
    )
    assert len(paths) >= 1
    assert paths[0].call_chain[0].context_id == "ROOT"


def test_scenario_k_baseline_comparison_stability():
    from analyzer.models.findings import Finding, SourceLocation, FindingSeverity, FindingConfidence, FindingCategory, EvidenceType
    from analyzer.models.results import AnalysisResult, RepositoryInfo
    from analyzer.comparison.diff import BaselineComparator

    loc = SourceLocation(file_path="app/views.py", line_start=85)
    
    f15 = Finding(
        id="finding-1",
        rule_id="SEC-PY-011",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="repo.find_by_id(uid)",
        description="SQL injection in find_by_id",
        remediation="Use parameterized queries",
        evidence={"call_chain": [{"caller": "handle_request", "callee": "find_by_id"}]},
    )

    f16 = Finding(
        id="finding-1",
        rule_id="SEC-PY-011",
        rule_name="SQL Injection",
        category=FindingCategory.SECURITY,
        evidence_type=EvidenceType.DETERMINISTIC,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        code_snippet="repo.find_by_id(uid)",
        description="SQL injection in find_by_id",
        remediation="Use parameterized queries",
        evidence={
            "call_chain": [{"caller": "handle_request", "callee": "find_by_id", "receiver_type": "UserRepository", "context_id": "c123"}],
            "context_metadata": {"k": 2},
        },
    )

    repo_info = RepositoryInfo(name="demo", local_path=".")
    r15 = AnalysisResult(repository=repo_info, security_findings=[f15])
    r16 = AnalysisResult(repository=repo_info, security_findings=[f16])

    diff = BaselineComparator.compare(current=r16, baseline=r15)
    assert diff.summary.unchanged_count == 1
    assert diff.summary.new_count == 0
    assert diff.summary.resolved_count == 0
    assert diff.findings[0].transition.value == "UNCHANGED"


