"""Abstract pipeline definition for the CodeSentinel analyzer engine."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from analyzer.models.results import AnalysisResult


class BaseAnalysisPipeline(ABC):
    """Abstract orchestrator contract for executing an end-to-end repository audit.
    
    Subclasses in Phase 2+ implement the concrete stages:
    1. Ingestion: Discover and catalog source files while respecting ignores.
    2. Detection: Identify languages and web frameworks.
    3. Parsing: Generate ASTs for Python, JavaScript, and TypeScript.
    4. Graphing: Extract import dependencies and construct NetworkX graph.
    5. Rule Evaluation: Execute registered security and architecture rules.
    6. Aggregation: Consolidate findings into the canonical AnalysisResult model.
    """

    @abstractmethod
    def run(self, target_path: Path | str, repository_name: Optional[str] = None) -> AnalysisResult:
        """Execute the full static analysis pipeline synchronously.
        
        Args:
            target_path: Path to the codebase directory to analyze.
            repository_name: Optional display name for the repository.
            
        Returns:
            Strongly-typed AnalysisResult model containing findings and graph.
            
        Raises:
            FileNotFoundError: If target_path does not exist.
            ValueError: If target_path is not a directory.
        """
        pass
