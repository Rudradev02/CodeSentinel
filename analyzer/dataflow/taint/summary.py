"""Cross-module data-flow summary models and extractor for CodeSentinel (Phase 22).

These structured per-file summary artifacts capture the taint-relevant interface of
each source file, allowing the incremental coordinator to selectively re-analyze only
affected cross-module data-flow chains rather than re-running full interprocedural analysis.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from analyzer.dataflow.taint.models import SinkCategory, SourceCategory
from analyzer.dataflow.callgraph.models import FunctionSummary


class ExportedTaintSource(BaseModel):
    """A taint source exported or accepted by a function in this file."""
    model_config = ConfigDict(frozen=True)

    function_qn: str
    param_index: int
    param_name: str
    source_category: SourceCategory
    line: int


class ExportedTaintSink(BaseModel):
    """A taint sink reachable within this file from caller inputs."""
    model_config = ConfigDict(frozen=True)

    function_qn: str
    param_index: int
    param_name: str
    sink_category: SinkCategory
    rule_id: str
    line: int


class ExportedSanitizer(BaseModel):
    """A sanitizer applied within this file to caller inputs."""
    model_config = ConfigDict(frozen=True)

    function_qn: str
    param_index: int
    sanitizer_categories: list[SinkCategory] = Field(default_factory=list)
    line: int


class CrossModuleTaintTransfer(BaseModel):
    """A taint transfer edge from imported function param to exported function return."""
    model_config = ConfigDict(frozen=True)

    caller_qn: str
    callee_qn: str
    callee_file: str
    from_param_index: int
    to_return: bool = False
    to_sink_category: Optional[SinkCategory] = None
    governing_condition: Optional[str] = None


class FileTaintSummary(BaseModel):
    """Per-file taint summary capturing cross-module taint-relevant interface."""

    file_path: str
    content_hash: str
    summary_schema_version: str = "1.0.0"

    # Exported taint facts
    exported_sources: list[ExportedTaintSource] = Field(default_factory=list)
    exported_sinks: list[ExportedTaintSink] = Field(default_factory=list)
    exported_sanitizers: list[ExportedSanitizer] = Field(default_factory=list)

    # Cross-module taint transfer edges
    taint_transfers: list[CrossModuleTaintTransfer] = Field(default_factory=list)

    # Intra-file taint summary hash (for cache validation)
    summary_hash: str = ""

    def compute_summary_hash(self) -> str:
        """Deterministic SHA-256 across all exported taint facts and transfers."""
        data = {
            "file_path": self.file_path,
            "content_hash": self.content_hash,
            "summary_schema_version": self.summary_schema_version,
            "exported_sources": [s.model_dump(mode="json") for s in sorted(self.exported_sources, key=lambda x: (x.function_qn, x.param_index, x.line))],
            "exported_sinks": [s.model_dump(mode="json") for s in sorted(self.exported_sinks, key=lambda x: (x.function_qn, x.param_index, x.line, x.rule_id))],
            "exported_sanitizers": [s.model_dump(mode="json") for s in sorted(self.exported_sanitizers, key=lambda x: (x.function_qn, x.param_index, x.line))],
            "taint_transfers": [t.model_dump(mode="json") for t in sorted(self.taint_transfers, key=lambda x: (x.caller_qn, x.callee_qn, x.from_param_index))],
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.summary_hash = digest
        return digest


class FileTaintSummaryExtractor:
    """Extracts FileTaintSummary artifacts from function summaries and call graphs."""

    @staticmethod
    def extract(
        file_path: str,
        content_hash: str,
        function_summaries: dict[str, FunctionSummary],
        call_graph: Optional[Any] = None,
    ) -> FileTaintSummary:
        """Extract a deterministic FileTaintSummary for a single file."""
        norm_file_path = file_path.replace("\\", "/").lstrip("./")

        exported_sources: list[ExportedTaintSource] = []
        exported_sinks: list[ExportedTaintSink] = []
        exported_sanitizers: list[ExportedSanitizer] = []
        taint_transfers: list[CrossModuleTaintTransfer] = []

        # Find all function summaries defined in this file
        for qn, summary in sorted(function_summaries.items()):
            sum_path = getattr(summary, "file_path", "").replace("\\", "/").lstrip("./")
            if sum_path != norm_file_path and not norm_file_path.endswith(sum_path) and not sum_path.endswith(norm_file_path):
                continue

            param_map = {getattr(param, "position", idx): param.name for idx, param in enumerate(getattr(summary, "parameters", []))}

            # Sinks
            for sink in getattr(summary, "sink_invocations", []):
                param_idx = getattr(sink, "receiving_param_index", getattr(sink, "param_index", 0))
                param_name = param_map.get(param_idx, getattr(sink, "param_name", f"arg_{param_idx}"))
                rule_id = getattr(sink, "sink_id", getattr(sink, "rule_id", "TAINT_SINK"))
                exported_sinks.append(
                    ExportedTaintSink(
                        function_qn=qn,
                        param_index=param_idx,
                        param_name=param_name,
                        sink_category=getattr(sink, "sink_category", SinkCategory.COMMAND_EXECUTE),
                        rule_id=rule_id,
                        line=getattr(sink, "line", 1),
                    )
                )

            # Sanitizers
            for san in getattr(summary, "sanitizer_applications", []):
                param_idx = getattr(san, "applied_to_param_index", getattr(san, "param_index", 0))
                cats = getattr(san, "effective_categories", getattr(san, "sanitizer_categories", []))
                if not cats and hasattr(san, "sink_category") and san.sink_category:
                    cats = [san.sink_category]
                exported_sanitizers.append(
                    ExportedSanitizer(
                        function_qn=qn,
                        param_index=param_idx,
                        sanitizer_categories=cats,
                        line=getattr(san, "line", 1),
                    )
                )

            # Taint transfers
            for transfer in getattr(summary, "taint_transfers", []):
                callee_file = getattr(transfer, "callee_file", "")
                callee_qn = getattr(transfer, "callee_function", "") or getattr(transfer, "callee_qn", "")
                if callee_file:
                    callee_file_norm = callee_file.replace("\\", "/").lstrip("./")
                    # If it's a cross-module transfer (different file)
                    if callee_file_norm != norm_file_path:
                        taint_transfers.append(
                            CrossModuleTaintTransfer(
                                caller_qn=qn,
                                callee_qn=callee_qn,
                                callee_file=callee_file_norm,
                                from_param_index=getattr(transfer, "from_param_index", 0),
                                to_return=getattr(transfer, "to_return", False),
                                to_sink_category=getattr(transfer, "to_sink_category", None),
                                governing_condition=getattr(transfer, "governing_condition", None),
                            )
                        )

        # Cross-module calls from CallGraph
        if call_graph is not None and hasattr(call_graph, "edges"):
            cg_functions = getattr(call_graph, "functions", {})
            seen_transfers = {(t.caller_qn, t.callee_qn, t.callee_file) for t in taint_transfers}
            for edge in call_graph.edges:
                edge_file = getattr(edge, "call_site_file", "").replace("\\", "/").lstrip("./")
                caller_qn = getattr(edge, "caller_qualified_name", getattr(edge, "caller_qn", ""))
                callee_qn = getattr(edge, "callee_qualified_name", getattr(edge, "callee_qn", ""))
                caller_def = cg_functions.get(caller_qn)
                caller_file = getattr(caller_def, "file_path", "").replace("\\", "/").lstrip("./") if caller_def else ""
                
                is_origin = (
                    edge_file == norm_file_path
                    or (caller_file and (caller_file == norm_file_path or norm_file_path.endswith(caller_file) or caller_file.endswith(norm_file_path)))
                )
                if is_origin:
                    callee_def = cg_functions.get(callee_qn)
                    if callee_def:
                        callee_path = getattr(callee_def, "file_path", "").replace("\\", "/").lstrip("./")
                        if callee_path and callee_path != norm_file_path and not norm_file_path.endswith(callee_path):
                            transfer_key = (caller_qn, callee_qn, callee_path)
                            if transfer_key not in seen_transfers:
                                seen_transfers.add(transfer_key)
                                taint_transfers.append(
                                    CrossModuleTaintTransfer(
                                        caller_qn=caller_qn,
                                        callee_qn=callee_qn,
                                        callee_file=callee_path,
                                        from_param_index=0,
                                    )
                                )

        summary_obj = FileTaintSummary(
            file_path=norm_file_path,
            content_hash=content_hash,
            exported_sources=exported_sources,
            exported_sinks=exported_sinks,
            exported_sanitizers=exported_sanitizers,
            taint_transfers=taint_transfers,
        )
        summary_obj.compute_summary_hash()
        return summary_obj


L6_LAYER = "L6"


def compute_taint_summary_cache_key(
    file_path: str,
    content_hash: str,
    cfg_dataflow_hash: str,
) -> str:
    """Derive deterministic cache key for a per-file taint summary (L6)."""
    norm_path = file_path.replace("\\", "/").lstrip("./")
    payload = f"{norm_path}:{content_hash}:{cfg_dataflow_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached_taint_summary(
    cache: Any,
    file_path: str,
    content_hash: str,
    cfg_dataflow_hash: str,
) -> Optional[FileTaintSummary]:
    """Retrieve and deserialize a FileTaintSummary from L6 cache."""
    key = compute_taint_summary_cache_key(file_path, content_hash, cfg_dataflow_hash)
    data = cache.get(L6_LAYER, key)
    if not data or not isinstance(data, dict):
        return None
    try:
        return FileTaintSummary.model_validate(data)
    except Exception:
        return None


def set_cached_taint_summary(
    cache: Any,
    file_path: str,
    content_hash: str,
    cfg_dataflow_hash: str,
    summary: FileTaintSummary,
) -> bool:
    """Store a FileTaintSummary in L6 cache."""
    key = compute_taint_summary_cache_key(file_path, content_hash, cfg_dataflow_hash)
    payload = summary.model_dump(mode="json")
    return cache.set(L6_LAYER, key, payload)


def is_taint_summary_cross_module_valid(
    summary: FileTaintSummary,
    current_file_hashes: dict[str, str],
    baseline_file_hashes: dict[str, str],
) -> bool:
    """Verify that all target files in cross-module transfers remain unchanged.
    
    If any callee file has changed content hash, this file's cross-module summary
    must be escalated for re-analysis.
    """
    for transfer in summary.taint_transfers:
        callee_file = transfer.callee_file.replace("\\", "/").lstrip("./")
        curr_hash = current_file_hashes.get(callee_file)
        base_hash = baseline_file_hashes.get(callee_file)
        if curr_hash is None or base_hash is None or curr_hash != base_hash:
            return False
    return True
