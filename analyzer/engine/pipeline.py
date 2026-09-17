"""Concrete implementation of the CodeSentinel repository analysis engine pipeline."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Optional

from analyzer.architecture.graph_builder import ArchitectureGraphBuilder
from analyzer.architecture.metrics import ArchitectureMetricsCalculator
from analyzer.dependencies.resolver import DependencyResolver
from analyzer.detection.frameworks import FrameworkDetector
from analyzer.detection.languages import LanguageDetector
from analyzer.ingestion.discovery import discover_repository_files
from analyzer.ingestion.ignore import IngestionConfig
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


class BaseAnalysisPipeline(ABC):
    """Abstract orchestrator contract for executing an end-to-end repository audit."""

    @abstractmethod
    def run(self, target_path: Path | str, repository_name: Optional[str] = None) -> AnalysisResult:
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

    def __init__(self, config: Optional[IngestionConfig] = None):
        self.config = config or IngestionConfig()
        # Initialize parser singletons
        self.py_parser = PythonParser()
        self.js_parser = JavaScriptParser()
        self.ts_parser = TypeScriptParser()

    def run(
        self,
        target_path: Path | str,
        repository_name: Optional[str] = None,
    ) -> AnalysisResult:
        """Execute the full static analysis pipeline synchronously.
        
        Args:
            target_path: Directory path to analyze.
            repository_name: Optional custom display name.
            
        Returns:
            Strongly-typed, fully-populated AnalysisResult.
            
        Raises:
            FileNotFoundError: If target_path does not exist.
            ValueError: If target_path is not a directory.
            PermissionError: If target_path cannot be read.
        """
        start_wall_time = time.time()
        started_at = datetime.now(timezone.utc)

        # 1. Ingestion Validation
        repo_path = validate_repository_path(target_path)
        name = repository_name or repo_path.name

        # 2. File Discovery
        discovered_files, manifest_paths = discover_repository_files(
            repo_path, config=self.config
        )

        # 3. Language & Framework Detection
        lang_distribution = LanguageDetector.calculate_distribution(discovered_files)
        total_loc = sum(f.line_count for f in discovered_files)

        fw_detector = FrameworkDetector(repo_path, manifest_paths)
        framework_evidence = fw_detector.detect(discovered_files)
        detected_framework_names = [fe.framework for fe in framework_evidence]

        # 4. Source Parsing into Normalized Representation
        parsed_files: list[ParsedFile] = []
        parsing_errors: list[ParsingError] = []

        for f in discovered_files:
            file_abs_path = Path(f.path)
            try:
                content = file_abs_path.read_text(encoding="utf-8", errors="replace")
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
        resolver = DependencyResolver(discovered_files)
        resolver.resolve_all(parsed_files)

        # 6. Architecture Graph Construction & Cycle Detection
        graph_builder = ArchitectureGraphBuilder(discovered_files, parsed_files)
        G, raw_nodes, raw_edges = graph_builder.build()
        arch_graph = ArchitectureMetricsCalculator.compute(G, raw_nodes, raw_edges)

        # 7. Metrics & Summary Aggregation
        completed_at = datetime.now(timezone.utc)
        duration_seconds = round(time.time() - start_wall_time, 3)

        repo_info = RepositoryInfo(
            name=name,
            local_path=str(repo_path),
            commit_hash=None,
            branch=None,
            detected_languages=lang_distribution,
            detected_frameworks=detected_framework_names,
            total_files=len(discovered_files),
            total_loc=total_loc,
        )

        arch_summary = ArchitectureSummary(
            total_modules=arch_graph.metrics.total_modules,
            circular_dependencies_count=arch_graph.metrics.circular_cycles_count,
            god_modules_count=0,  # Phase 3 rule detection
            total_findings=0,     # Phase 3 rule detection
        )

        metadata = AnalysisMetadata(
            engine_version="0.1.0",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
        )

        return AnalysisResult(
            repository=repo_info,
            status=AnalysisStatus.COMPLETED,
            metadata=metadata,
            security_summary=SecuritySummary(),
            architecture_summary=arch_summary,
            security_findings=[],
            architecture_findings=[],
            graph=arch_graph,
            files=discovered_files,
            framework_details=framework_evidence,
            parsing_errors=parsing_errors,
        )
