"""Unit tests for Phase 22 FileTaintSummary and FileTaintSummaryExtractor."""

from pathlib import Path

from analyzer.dataflow.callgraph.models import (
    FunctionSummary,
    ParameterDef,
    SummarySanitizerApplication,
    SummarySinkInvocation,
    TaintTransfer,
)
from analyzer.dataflow.taint.models import SinkCategory, SourceCategory, TaintState
from analyzer.dataflow.taint.summary import (
    CrossModuleTaintTransfer,
    ExportedSanitizer,
    ExportedTaintSink,
    ExportedTaintSource,
    FileTaintSummary,
    FileTaintSummaryExtractor,
    compute_taint_summary_cache_key,
    get_cached_taint_summary,
    is_taint_summary_cross_module_valid,
    set_cached_taint_summary,
)
from analyzer.incremental.cache import DiskAnalysisCache, InMemoryAnalysisCache


def test_file_taint_summary_extraction():
    """Verify extraction of exported facts and cross-module transfers from FunctionSummary."""
    fn_summary = FunctionSummary(
        qualified_name="api.endpoints.create_user",
        file_path="api/endpoints.py",
        parameters=[
            ParameterDef(name="raw_input", position=0, type_hint="str"),
            ParameterDef(name="user_id", position=1, type_hint="int"),
        ],
        sink_invocations=[
            SummarySinkInvocation(
                sink_id="SEC-PY-001",
                sink_category=SinkCategory.SQL_EXECUTE,
                receiving_param_index=0,
                line=25,
            )
        ],
        sanitizer_applications=[
            SummarySanitizerApplication(
                sanitizer_id="shlex.quote",
                applied_to_param_index=1,
                effective_categories=[SinkCategory.COMMAND_EXECUTE],
                line=28,
            )
        ],
        taint_transfers=[
            TaintTransfer(
                from_param_index=0,
                to_return=True,
            )
        ],
    )

    from analyzer.dataflow.callgraph.models import CallGraph, CallEdge, FunctionDefinition, CallResolutionType
    cg = CallGraph(
        functions={
            "api.endpoints.create_user": FunctionDefinition(
                id="fn-1",
                qualified_name="api.endpoints.create_user",
                file_path="api/endpoints.py",
                language="PYTHON",
                name="create_user",
                line_start=1,
                line_end=30,
            ),
            "services.auth.hash_token": FunctionDefinition(
                id="fn-2",
                qualified_name="services.auth.hash_token",
                file_path="services/auth.py",
                language="PYTHON",
                name="hash_token",
                line_start=1,
                line_end=20,
            ),
        },
        edges=[
            CallEdge(
                id="edge-1",
                caller_qualified_name="api.endpoints.create_user",
                callee_qualified_name="services.auth.hash_token",
                call_site_file="api/endpoints.py",
                call_site_line=26,
                resolution_type=CallResolutionType.RESOLVED_IMPORT,
            )
        ],
    )

    summaries = {"api.endpoints.create_user": fn_summary}
    summary = FileTaintSummaryExtractor.extract(
        file_path="api/endpoints.py",
        content_hash="content_hash_123",
        function_summaries=summaries,
        call_graph=cg,
    )

    assert summary.file_path == "api/endpoints.py"
    assert summary.content_hash == "content_hash_123"
    assert len(summary.exported_sinks) == 1
    assert summary.exported_sinks[0].sink_category == SinkCategory.SQL_EXECUTE
    assert summary.exported_sinks[0].function_qn == "api.endpoints.create_user"

    assert len(summary.exported_sanitizers) == 1
    assert summary.exported_sanitizers[0].sanitizer_categories == [SinkCategory.COMMAND_EXECUTE]

    assert len(summary.taint_transfers) == 1
    assert summary.taint_transfers[0].callee_file == "services/auth.py"
    assert summary.taint_transfers[0].caller_qn == "api.endpoints.create_user"
    assert len(summary.summary_hash) == 64


def test_taint_summary_hash_determinism():
    """Verify FileTaintSummary computes deterministic summary hashes."""
    s1 = FileTaintSummary(
        file_path="app/views.py",
        content_hash="cnt_1",
        exported_sources=[
            ExportedTaintSource(
                function_qn="app.views.login",
                param_index=0,
                param_name="token",
                source_category=SourceCategory.HTTP_PARAM,
                line=10,
            )
        ],
    )
    s2 = FileTaintSummary(
        file_path="app/views.py",
        content_hash="cnt_1",
        exported_sources=[
            ExportedTaintSource(
                function_qn="app.views.login",
                param_index=0,
                param_name="token",
                source_category=SourceCategory.HTTP_PARAM,
                line=10,
            )
        ],
    )

    h1 = s1.compute_summary_hash()
    h2 = s2.compute_summary_hash()
    assert h1 == h2


def test_taint_summary_cache_key_and_storage():
    """Verify caching and retrieval of FileTaintSummary in InMemoryAnalysisCache."""
    cache = InMemoryAnalysisCache()
    summary = FileTaintSummary(
        file_path="app/views.py",
        content_hash="cnt_hash_1",
        exported_sinks=[
            ExportedTaintSink(
                function_qn="app.views.exec",
                param_index=0,
                param_name="cmd",
                sink_category=SinkCategory.COMMAND_EXECUTE,
                rule_id="SEC-PY-002",
                line=30,
            )
        ],
    )

    k = compute_taint_summary_cache_key("app/views.py", "cnt_hash_1", "cfg_hash_1")
    assert len(k) == 64

    ok = set_cached_taint_summary(cache, "app/views.py", "cnt_hash_1", "cfg_hash_1", summary)
    assert ok is True

    cached = get_cached_taint_summary(cache, "app/views.py", "cnt_hash_1", "cfg_hash_1")
    assert cached is not None
    assert cached.file_path == "app/views.py"
    assert len(cached.exported_sinks) == 1
    assert cached.exported_sinks[0].rule_id == "SEC-PY-002"

    # Miss on different content hash
    assert get_cached_taint_summary(cache, "app/views.py", "cnt_hash_2", "cfg_hash_1") is None


def test_taint_summary_cross_module_validity():
    """Verify is_taint_summary_cross_module_valid detects changed external dependencies."""
    summary = FileTaintSummary(
        file_path="app/views.py",
        content_hash="cnt_1",
        taint_transfers=[
            CrossModuleTaintTransfer(
                caller_qn="app.views.index",
                callee_qn="app.utils.sanitize",
                callee_file="app/utils.py",
                from_param_index=0,
                to_return=True,
            )
        ],
    )

    # 1. Unchanged callee file -> valid
    base_hashes = {"app/utils.py": "util_hash_v1"}
    curr_hashes = {"app/utils.py": "util_hash_v1"}
    assert is_taint_summary_cross_module_valid(summary, curr_hashes, base_hashes) is True

    # 2. Callee file was modified -> invalid
    curr_hashes_modified = {"app/utils.py": "util_hash_v2"}
    assert is_taint_summary_cross_module_valid(summary, curr_hashes_modified, base_hashes) is False

    # 3. Callee file missing from current -> invalid
    curr_hashes_missing = {}
    assert is_taint_summary_cross_module_valid(summary, curr_hashes_missing, base_hashes) is False


def test_taint_summary_disk_persistence(tmp_path: Path):
    """Verify FileTaintSummary round-trips through DiskAnalysisCache."""
    cache = DiskAnalysisCache(cache_dir=tmp_path)
    summary = FileTaintSummary(
        file_path="core/engine.py",
        content_hash="engine_hash_1",
        exported_sources=[],
    )

    set_cached_taint_summary(cache, "core/engine.py", "engine_hash_1", "cfg_1", summary)

    cache2 = DiskAnalysisCache(cache_dir=tmp_path)
    retrieved = get_cached_taint_summary(cache2, "core/engine.py", "engine_hash_1", "cfg_1")
    assert retrieved is not None
    assert retrieved.file_path == "core/engine.py"
