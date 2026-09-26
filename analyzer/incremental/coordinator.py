"""Incremental analysis coordinator orchestrating layered cache reuse and targeted re-analysis (Phase 21)."""

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Callable, Optional

from analyzer.incremental.cache import AnalysisCache, DiskAnalysisCache, InMemoryAnalysisCache
from analyzer.incremental.config_fingerprint import compute_scoped_config_fingerprint
from analyzer.incremental.fingerprints import (
    compute_repository_fingerprints,
    diff_fingerprints,
    normalize_relative_path,
)
from analyzer.incremental.impact import build_impact_set
from analyzer.incremental.keys import compute_repo_namespace_id
from analyzer.incremental.models import FileFingerprint, IncrementalStats
from analyzer.incremental.reconciliation import FindingReconciler
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.ingestion.git import get_git_metadata
from analyzer.ingestion.ignore import IgnoreEngine, IngestionConfig
from analyzer.ingestion.repository import validate_repository_path
from analyzer.models.errors import AnalysisCancelledError
from analyzer.models.findings import Finding
from analyzer.models.results import AnalysisResult


class IncrementalAnalysisCoordinator:
    """Orchestrates deterministic incremental static analysis over layered caches."""

    def __init__(
        self,
        cache: Optional[AnalysisCache] = None,
        cache_root: Optional[Path | str] = None,
    ):
        self.cache = cache
        self.cache_root = Path(cache_root) if cache_root else None

    def run(
        self,
        target_path: Path | str,
        pipeline: Any,
        repository_name: Optional[str] = None,
        analysis_config: Optional[Any] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        affected_files: Optional[set[str]] = None,
    ) -> AnalysisResult:
        """Execute incremental repository analysis using cached artifacts where valid."""
        def _report(stage: str, percent: int, message: str) -> None:
            if is_cancelled and is_cancelled():
                raise AnalysisCancelledError("Analysis was cancelled by user")
            if on_progress:
                on_progress(stage, percent, message)

        start_wall_time = time.time()
        _report("INGESTION", 5, "Validating repository path and initializing cache...")

        repo_path = validate_repository_path(target_path)
        git_meta = get_git_metadata(repo_path)
        repo_ns = compute_repo_namespace_id(
            repo_root=repo_path,
            remote_url=None,
            root_commit=git_meta.commit_hash,
        )

        # Initialize disk cache if none provided
        if self.cache is None:
            root_dir = self.cache_root or (repo_path / ".codesentinel_cache")
            self.cache = DiskAnalysisCache(cache_root=root_dir, repo_namespace_id=repo_ns)

        # 1. File Discovery & Current Fingerprints
        _report("DISCOVERY", 12, "Discovering repository files and computing fingerprints...")
        ignore_engine = IgnoreEngine(repo_path)
        if analysis_config and getattr(analysis_config, "paths_exclude", None):
            for pat in analysis_config.paths_exclude:
                if pat not in ignore_engine.custom_patterns:
                    ignore_engine.custom_patterns.append(pat)

        discovered_files, manifest_paths = discover_repository_files(
            repo_path, config=IngestionConfig(), ignore_engine=ignore_engine
        )

        curr_fps = compute_repository_fingerprints(repo_path, discovered_files)
        curr_cfg_fp = compute_scoped_config_fingerprint(analysis_config)

        # 2. Retrieve previous fingerprints and config
        _report("FINGERPRINTING", 20, "Diffing source fingerprints and active configuration...")
        prev_fps_raw = self.cache.get("L1", "manifest")
        prev_cfg_fp_raw = self.cache.get("CONFIG", "fingerprint")

        prev_fps: Optional[dict[str, FileFingerprint]] = None
        if prev_fps_raw and isinstance(prev_fps_raw, dict):
            try:
                prev_fps = {p: FileFingerprint(**fp_data) for p, fp_data in prev_fps_raw.items()}
            except Exception:
                prev_fps = None

        # Check full cache hit condition
        if prev_fps is not None and prev_cfg_fp_raw is not None:
            mod_paths, add_paths, del_paths, ren_paths = diff_fingerprints(prev_fps, curr_fps)
            cfg_identical = (prev_cfg_fp_raw.get("global_hash") == curr_cfg_fp.global_hash)

            if not mod_paths and not add_paths and not del_paths and not ren_paths and cfg_identical:
                # 100% unchanged! Check L9 result cache
                cached_result_raw = self.cache.get("L9", "analysis_result")
                if cached_result_raw:
                    try:
                        cached_result = AnalysisResult(**cached_result_raw)
                        # Attach incremental stats
                        stats = IncrementalStats(
                            analysis_mode="incremental",
                            files_discovered=len(discovered_files),
                            files_reused=len(discovered_files),
                            files_reanalyzed=0,
                            cache_hits=len(discovered_files),
                            cache_misses=0,
                            hit_ratio=1.0,
                            estimated_time_saved_seconds=round(time.time() - start_wall_time, 2),
                        )
                        if cached_result.call_graph_summary is None:
                            cached_result.call_graph_summary = {}
                        dumped_stats = stats.model_dump()
                        cached_result.call_graph_summary["incremental"] = dumped_stats
                        cached_result.call_graph_summary["incremental_stats"] = dumped_stats
                        _report("COMPLETED", 100, "Incremental analysis completed (100% cache hit).")
                        return cached_result
                    except Exception:
                        pass  # Safe fallback to recomputation

        # 3. Targeted Re-analysis & Invalidation
        _report("IMPACT_ANALYSIS", 30, "Computing reverse dependency and contract impact closure...")

        # If cold cache, run full analysis and populate cache
        if prev_fps is None or prev_cfg_fp_raw is None:
            result = pipeline.run(
                target_path=target_path,
                repository_name=repository_name,
                analysis_config=analysis_config,
                on_progress=on_progress,
                is_cancelled=is_cancelled,
                cache=self.cache,
                affected_files=affected_files,
            )
            # Populate cache
            self._save_cache_artifacts(curr_fps, curr_cfg_fp, result)
            stats = IncrementalStats(
                analysis_mode="incremental (cold start)",
                files_discovered=len(discovered_files),
                files_reused=0,
                files_reanalyzed=len(discovered_files),
                cache_hits=0,
                cache_misses=len(discovered_files),
                hit_ratio=0.0,
            )
            if result.call_graph_summary is None:
                result.call_graph_summary = {}
            dumped_stats = stats.model_dump()
            result.call_graph_summary["incremental"] = dumped_stats
            result.call_graph_summary["incremental_stats"] = dumped_stats
            return result

        # Warm cache: Compute diff and impact closure
        mod_paths, add_paths, del_paths, ren_paths = diff_fingerprints(prev_fps, curr_fps)
        all_discovered_paths = {normalize_relative_path(f.relative_path) for f in discovered_files}

        # Build approximate dependency graph from previous result or file scans
        cached_dep_graph = self.cache.get("L3", "dependency_graph") or {}

        impact = build_impact_set(
            directly_changed=mod_paths,
            added_files=add_paths,
            deleted_files=del_paths,
            renamed_files=ren_paths,
            all_discovered_files=all_discovered_paths,
            dependency_graph=cached_dep_graph,
        )

        # Check cross-module taint summaries for escalation
        taint_summary_hits = 0
        taint_summary_misses = 0
        if getattr(analysis_config, "enable_taint_summaries", False):
            curr_hashes = {p: fp.content_hash for p, fp in curr_fps.items()}
            prev_hashes = {p: fp.content_hash for p, fp in prev_fps.items()} if prev_fps else {}
            unaffected = all_discovered_paths - impact.affected_files
            escalated_files: set[str] = set()

            from analyzer.dataflow.taint.summary import get_cached_taint_summary, is_taint_summary_cross_module_valid
            for p in sorted(unaffected):
                summary = get_cached_taint_summary(self.cache, p, curr_hashes.get(p, ""), curr_cfg_fp.cfg_dataflow_hash)
                if summary is not None:
                    taint_summary_hits += 1
                    if not is_taint_summary_cross_module_valid(summary, curr_hashes, prev_hashes):
                        escalated_files.add(p)
                else:
                    taint_summary_misses += 1

            if escalated_files:
                impact.affected_files.update(escalated_files)
                impact.reusable_files.difference_update(escalated_files)

        if affected_files:
            impact.affected_files.update(affected_files)

        _report("REANALYZING", 50, f"Re-analyzing {len(impact.affected_files)} affected files...")

        # Run pipeline
        fresh_result = pipeline.run(
            target_path=target_path,
            repository_name=repository_name,
            analysis_config=analysis_config,
            on_progress=on_progress,
            is_cancelled=is_cancelled,
            cache=self.cache,
            affected_files=impact.affected_files,
        )

        # 4. Reconcile findings
        _report("FINDING_RECONCILIATION", 85, "Reconciling findings and verifying invariants...")
        prev_findings_raw = self.cache.get("L9", "findings") or []
        prev_findings = [Finding(**f) for f in prev_findings_raw]

        current_findings = fresh_result.security_findings + fresh_result.architecture_findings
        reconciled_findings, counts = FindingReconciler.reconcile(
            previous_findings=prev_findings,
            newly_computed_findings=current_findings,
            affected_files=impact.affected_files,
            deleted_files=impact.deleted_files,
        )

        # Update findings on fresh_result
        fresh_result.security_findings = [f for f in reconciled_findings if f.category == "SECURITY"]
        fresh_result.architecture_findings = [f for f in reconciled_findings if f.category == "ARCHITECTURE"]

        # Populate and persist cache
        self._save_cache_artifacts(curr_fps, curr_cfg_fp, fresh_result)

        # Compute telemetry stats
        reused_count = len(impact.reusable_files)
        reanalyzed_count = len(impact.affected_files)
        total_count = len(discovered_files)
        hit_ratio = round(reused_count / max(total_count, 1), 3)

        reason_counts: dict[str, int] = {}
        for r in impact.invalidation_reasons.values():
            reason_counts[r.value] = reason_counts.get(r.value, 0) + 1

        stats = IncrementalStats(
            analysis_mode="incremental",
            files_discovered=total_count,
            files_reused=reused_count,
            files_reanalyzed=reanalyzed_count,
            cache_hits=reused_count,
            cache_misses=reanalyzed_count,
            hit_ratio=hit_ratio,
            composition_hits=reused_count,
            composition_misses=reanalyzed_count,
            taint_summary_hits=taint_summary_hits,
            taint_summary_misses=taint_summary_misses,
            estimated_time_saved_seconds=round(max(0.0, (total_count - reanalyzed_count) * 0.05), 2),
            invalidations_by_reason=reason_counts,
        )

        if fresh_result.call_graph_summary is None:
            fresh_result.call_graph_summary = {}
        dumped_stats = stats.model_dump()
        fresh_result.call_graph_summary["incremental"] = dumped_stats
        fresh_result.call_graph_summary["incremental_stats"] = dumped_stats

        _report("COMPLETED", 100, "Incremental analysis completed successfully.")
        return fresh_result

    def _save_cache_artifacts(
        self,
        fingerprints: dict[str, FileFingerprint],
        config_fingerprint: Any,
        result: AnalysisResult,
    ) -> None:
        """Persist analysis state to cache layers L1 through L9."""
        if not self.cache:
            return

        # L1: Manifest of fingerprints
        fps_dict = {p: fp.model_dump() for p, fp in fingerprints.items()}
        self.cache.set("L1", "manifest", fps_dict)

        # Config fingerprint
        self.cache.set("CONFIG", "fingerprint", config_fingerprint.model_dump())

        # L3: Dependency graph
        dep_graph: dict[str, list[str]] = {}
        if hasattr(result, "graph") and result.graph and hasattr(result.graph, "edges"):
            for e in result.graph.edges:
                dep_graph.setdefault(e.source, []).append(e.target)
        self.cache.set("L3", "dependency_graph", dep_graph)

        # L9: Findings and Full Result
        all_findings = [f.model_dump() for f in (result.security_findings + result.architecture_findings)]
        self.cache.set("L9", "findings", all_findings)
        self.cache.set("L9", "analysis_result", result.model_dump(mode="json"))
