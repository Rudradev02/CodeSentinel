"""Concrete implementation of the CodeSentinel repository analysis engine pipeline."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Callable, Optional

from analyzer.models.errors import AnalysisCancelledError

from analyzer.architecture.components import ComponentGraphBuilder
from analyzer.architecture.graph_builder import ArchitectureGraphBuilder
from analyzer.architecture.health import HealthScoreCalculator
from analyzer.architecture.metrics import ArchitectureMetricsCalculator
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.detection.frameworks import FrameworkDetector
from analyzer.detection.languages import LanguageDetector
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.ingestion.git import get_git_metadata
from analyzer.ingestion.ignore import IgnoreEngine, IngestionConfig
from analyzer.ingestion.repository import validate_repository_path
from analyzer.models.metadata import ParsingError
from analyzer.models.parse import ParsedFile
from analyzer.models.results import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisStatus,
    ArchitectureSummary,
    RepositoryInfo,
    SecuritySummary,
)
from analyzer.parsing.javascript_parser import JavaScriptParser
from analyzer.parsing.python_parser import PythonParser
from analyzer.parsing.typescript_parser import TypeScriptParser
from analyzer.config.settings import AnalysisConfig
from analyzer.rules.engine import RuleEngine
from analyzer.rules.registry import RuleRegistry


class BaseAnalysisPipeline(ABC):
    """Abstract orchestrator contract for executing an end-to-end repository audit."""

    @abstractmethod
    def run(
        self,
        target_path: Path | str,
        repository_name: Optional[str] = None,
        analysis_config: Optional[AnalysisConfig] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> AnalysisResult:
        """Execute the full static analysis pipeline synchronously."""
        pass



class AnalysisPipeline(BaseAnalysisPipeline):
    """End-to-end repository analysis engine for Phase 2.
    
    Executes:
    1. Path validation & safe ingestion
    2. File discovery with .gitignore & .sentinelignore
    3. Deterministic language & evidence-based framework detection
    4. Source parsing via Python AST & Tree-sitter JS/TS
    5. Dependency extraction & local module resolution
    6. Directed architecture graph construction (NetworkX)
    7. Metrics calculation & circular dependency cycle detection
    8. Canonical AnalysisResult serialization
    """

    def __init__(
        self,
        config: Optional[IngestionConfig] = None,
        analysis_config: Optional[AnalysisConfig] = None,
    ):
        self.config = config or IngestionConfig()
        self.analysis_config = analysis_config or AnalysisConfig()
        # Initialize parser singletons
        self.py_parser = PythonParser()
        self.js_parser = JavaScriptParser()
        self.ts_parser = TypeScriptParser()

    def run(
        self,
        target_path: Path | str,
        repository_name: Optional[str] = None,
        analysis_config: Optional[AnalysisConfig] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> AnalysisResult:
        """Execute the full static analysis pipeline synchronously.
        
        Args:
            target_path: Directory path to analyze.
            repository_name: Optional custom display name.
            analysis_config: Optional configuration overriding pipeline defaults.
            on_progress: Optional progress callback receiving (stage, percent, message).
            is_cancelled: Optional cooperative cancellation check returning True if cancelled.
            
        Returns:
            Strongly-typed, fully-populated AnalysisResult.
            
        Raises:
            AnalysisCancelledError: If cancellation was requested during execution.
            FileNotFoundError: If target_path does not exist.
            ValueError: If target_path is not a directory.
            PermissionError: If target_path cannot be read.
        """
        def _report(stage: str, percent: int, message: str) -> None:
            if is_cancelled and is_cancelled():
                raise AnalysisCancelledError("Analysis was cancelled by user")
            if on_progress:
                on_progress(stage, percent, message)

        start_wall_time = time.time()
        started_at = datetime.now(timezone.utc)

        # 1. Ingestion Validation
        _report("INGESTION", 5, "Validating repository path...")
        repo_path = validate_repository_path(target_path)
        name = repository_name or repo_path.name

        # 2. File Discovery
        _report("DISCOVERY", 15, "Discovering repository files...")
        ignore_engine = IgnoreEngine(repo_path)
        if analysis_config and analysis_config.paths_exclude:
            for pat in analysis_config.paths_exclude:
                if pat not in ignore_engine.custom_patterns:
                    ignore_engine.custom_patterns.append(pat)
        discovered_files, manifest_paths = discover_repository_files(
            repo_path, config=self.config, ignore_engine=ignore_engine
        )

        # 3. Language & Framework Detection
        _report("DETECTION", 25, "Detecting languages and frameworks...")
        lang_distribution = LanguageDetector.calculate_distribution(discovered_files)
        total_loc = sum(f.line_count for f in discovered_files)

        fw_detector = FrameworkDetector(repo_path, manifest_paths)
        framework_evidence = fw_detector.detect(discovered_files)
        detected_framework_names = [fe.framework for fe in framework_evidence]

        # 4. Source Parsing into Normalized Representation
        _report("PARSING", 45, "Parsing source code syntax trees...")
        parsed_files: list[ParsedFile] = []
        parsing_errors: list[ParsingError] = []
        file_contents: dict[str, str] = {}

        for f in discovered_files:
            file_abs_path = Path(f.path)
            norm_rel = f.relative_path.replace("\\", "/")
            try:
                content = file_abs_path.read_text(encoding="utf-8", errors="replace")
                file_contents[norm_rel] = content
            except Exception as read_err:
                parsing_errors.append(
                    ParsingError(
                        file_path=f.relative_path,
                        error_message=f"File read error: {str(read_err)}",
                    )
                )
                continue

            parsed: Optional[ParsedFile] = None
            if f.language == "PYTHON":
                parsed = self.py_parser.parse(file_abs_path, f.relative_path, content)
            elif f.language == "JAVASCRIPT":
                parsed = self.js_parser.parse(file_abs_path, f.relative_path, content)
            elif f.language == "TYPESCRIPT":
                parsed = self.ts_parser.parse(file_abs_path, f.relative_path, content)

            if parsed:
                parsed_files.append(parsed)
                # Collect non-fatal parsing errors
                for pe in parsed.errors:
                    parsing_errors.append(
                        ParsingError(
                            file_path=f.relative_path,
                            error_message=pe.message,
                            line_number=pe.line,
                            column_number=pe.column,
                        )
                    )

        # 5. Dependency Resolution
        _report("DEPENDENCIES", 55, "Resolving module dependencies...")
        resolver = DependencyResolver(discovered_files, repo_root=repo_path)
        resolver.resolve_all(parsed_files)

        # 6. Architecture Graph Construction & Cycle Detection
        _report("ARCHITECTURE_GRAPH", 60, "Constructing architecture and component graphs...")
        graph_builder = ArchitectureGraphBuilder(discovered_files, parsed_files)
        G, raw_nodes, raw_edges = graph_builder.build()
        arch_graph = ArchitectureMetricsCalculator.compute(G, raw_nodes, raw_edges)

        active_analysis_config = analysis_config or self.analysis_config

        # Phase 7: Component Graph Construction & Packaging Metrics
        max_depth = getattr(active_analysis_config, "max_component_depth", 2)
        comp_builder = ComponentGraphBuilder(
            files=discovered_files,
            file_nodes=arch_graph.nodes,
            file_edges=arch_graph.edges,
            max_depth=max_depth,
        )
        component_graph = comp_builder.build()

        # Phase 13: Centrality Metrics Calculation
        _report("CENTRALITY", 65, "Calculating repository component centrality metrics...")
        from analyzer.architecture.centrality import CentralityCalculator
        component_graph = CentralityCalculator.compute(component_graph)
        arch_graph.component_graph = component_graph

        # Phase 15: Call Graph Construction & Interprocedural Data-Flow
        call_graph_summary = None
        interprocedural_paths = []
        disable_interprocedural = getattr(active_analysis_config, "disable_interprocedural", False)

        if not disable_interprocedural:
            _report("CALL_GRAPH", 72, "Constructing static call graph and resolving call sites...")
            from analyzer.dataflow.callgraph.graph_builder import CallGraphBuilder
            from analyzer.dataflow.callgraph.summarizer import FunctionSummarizer
            from analyzer.dataflow.interprocedural.propagator import InterproceduralTaintPropagator

            cg_builder = CallGraphBuilder(
                max_call_edges=20000,
                is_cancelled=is_cancelled,
            )
            ast_cache: dict[str, Any] = {}
            call_graph = cg_builder.build_call_graph(
                parsed_files=parsed_files,
                file_contents=file_contents,
                ast_cache=ast_cache,
            )

            _report("INTER_PROCEDURAL", 80, "Generating function summaries and analyzing interprocedural taint...")
            summarizer = FunctionSummarizer(
                is_cancelled=is_cancelled,
            )
            summaries = summarizer.summarize_all(
                functions=list(call_graph.functions.values()),
                parsed_files=parsed_files,
                file_contents=file_contents,
                ast_cache=ast_cache,
                call_graph=call_graph,
            )

            inter_propagator = InterproceduralTaintPropagator(
                call_graph=call_graph,
                summaries=summaries,
                max_call_depth=getattr(active_analysis_config, "max_call_depth", 5),
                disable_type_inference=getattr(active_analysis_config, "disable_type_inference", False),
                disable_context_sensitivity=getattr(active_analysis_config, "disable_context_sensitivity", False),
                disable_alias_analysis=getattr(active_analysis_config, "disable_alias_analysis", False),
                disable_field_sensitivity=getattr(active_analysis_config, "disable_field_sensitivity", False),
                max_points_to_candidates=getattr(active_analysis_config, "max_points_to_candidates", 4),
                max_fields_per_object=getattr(active_analysis_config, "max_fields_per_object", 16),
                max_objects_per_function=getattr(active_analysis_config, "max_objects_per_function", 32),
                max_alias_iterations=getattr(active_analysis_config, "max_alias_iterations", 5),
                max_k=getattr(active_analysis_config, "max_k", 2),
                max_contexts_per_function=getattr(active_analysis_config, "max_contexts_per_function", 8),
                is_cancelled=is_cancelled,
            )
            interprocedural_paths = inter_propagator.analyze_repository(
                parsed_files=parsed_files,
                file_contents=file_contents,
                ast_cache=ast_cache,
            )

            semantic_summary = inter_propagator.get_semantic_summary()
            call_graph_summary = {
                "total_functions": len(call_graph.functions),
                "total_call_edges": len(call_graph.edges),
                "resolved_local": call_graph.resolution_stats.resolved_local,
                "resolved_import": call_graph.resolution_stats.resolved_import,
                "unresolved": call_graph.resolution_stats.unresolved,
                "resolution_rate": call_graph.resolution_stats.resolution_rate,
                "summarized_functions": sum(1 for s in summaries.values() if s.is_summarized),
                "unsummarized_functions": sum(1 for s in summaries.values() if not s.is_summarized),
                "interprocedural_findings_count": len(interprocedural_paths),
                "max_call_depth_reached": max((p.total_depth for p in interprocedural_paths), default=0),
                "type_resolution": semantic_summary["type_resolution"],
                "context_sensitivity": semantic_summary["context_sensitivity"],
            }
            if "alias_analysis" in semantic_summary:
                call_graph_summary["alias_analysis"] = semantic_summary["alias_analysis"]

        # Phase 13: Data-Flow & Taint Analysis
        _report("DATA_FLOW", 85, "Analyzing intraprocedural data-flow and taint traces...")

        # 9. Security & Architecture Rule Engine Execution
        _report("RULES", 92, "Evaluating security and architectural rules...")

        registry = RuleRegistry(load_defaults=True)
        registry.apply_configuration(active_analysis_config)
        rule_engine = RuleEngine(registry=registry)

        security_findings, security_summary = rule_engine.analyze_security(
            files=discovered_files,
            file_contents=file_contents,
            parsed_files=parsed_files,
            detected_frameworks=detected_framework_names,
            interprocedural_paths=interprocedural_paths,
        )
        architecture_findings, arch_summary = rule_engine.analyze_architecture(
            graph=arch_graph,
            parsed_files=parsed_files,
        )

        # Phase 7: Deterministic Codebase Health & Risk Scoring
        _report("HEALTH_SCORING", 97, "Computing codebase health scores...")
        codebase_health = HealthScoreCalculator.compute(
            security_findings=security_findings,
            architecture_findings=architecture_findings,
        )

        # Ensure collections are strictly deterministically ordered
        framework_evidence.sort(key=lambda fe: fe.framework)
        parsing_errors.sort(
            key=lambda pe: (
                pe.file_path,
                pe.line_number or 0,
                pe.column_number or 0,
                pe.error_message,
            )
        )

        # Phase 6: Collect and sort dependency diagnostics
        dependency_diagnostics = sorted(
            resolver.diagnostics,
            key=lambda d: (d.file_path, d.line_number or 0, d.source_module),
        )

        # 8. Metrics & Metadata Aggregation
        completed_at = datetime.now(timezone.utc)
        duration_seconds = round(time.time() - start_wall_time, 3)

        git_meta = get_git_metadata(repo_path)
        repo_info = RepositoryInfo(
            name=name,
            local_path=str(repo_path),
            commit_hash=git_meta.commit_hash,
            branch=git_meta.branch,
            is_dirty=git_meta.is_dirty,
            detected_languages=lang_distribution,
            detected_frameworks=sorted(detected_framework_names),
            total_files=len(discovered_files),
            total_loc=total_loc,
        )

        metadata = AnalysisMetadata(
            engine_version="0.1.0",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
        )

        _report("COMPLETED", 100, "Analysis completed successfully.")

        return AnalysisResult(
            repository=repo_info,
            status=AnalysisStatus.COMPLETED,
            metadata=metadata,
            security_summary=security_summary,
            architecture_summary=arch_summary,
            security_findings=security_findings,
            architecture_findings=architecture_findings,
            graph=arch_graph,
            files=discovered_files,
            framework_details=framework_evidence,
            parsing_errors=parsing_errors,
            dependency_diagnostics=dependency_diagnostics,
            health=codebase_health,
            call_graph_summary=call_graph_summary,
        )


