"""Deterministic JSON reporter for machine-readable analysis results."""

import json
from analyzer.models.results import AnalysisResult
from analyzer.reporting.base import BaseReporter


class JsonReporter(BaseReporter):
    """Formats AnalysisResult into deterministic, canonical JSON.
    
    Guarantees:
    - Pre-sorts all nested collections (findings, files, errors, graph elements)
    - Serializes with sorted dictionary keys (sort_keys=True)
    - Preserves ISO-8601 timestamps and typed enum values
    """

    def render(self, result: AnalysisResult) -> str:
        """Render AnalysisResult as deterministic JSON string.
        
        Args:
            result: Strongly-typed AnalysisResult.
            
        Returns:
            Deterministic indented JSON string.
        """
        # Ensure collections inside result are strictly pre-sorted
        result.security_findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line_start,
                f.location.col_start or 0,
                f.rule_id,
            )
        )
        result.architecture_findings.sort(
            key=lambda f: (
                f.location.file_path,
                f.location.line_start,
                f.location.col_start or 0,
                f.rule_id,
            )
        )
        result.files.sort(key=lambda f: f.relative_path)
        result.framework_details.sort(key=lambda fe: fe.framework)
        result.parsing_errors.sort(
            key=lambda pe: (
                pe.file_path,
                pe.line_number or 0,
                pe.column_number or 0,
                pe.error_message,
            )
        )

        if result.graph:
            result.graph.nodes.sort(key=lambda n: n.id)
            result.graph.edges.sort(
                key=lambda e: (
                    e.source,
                    e.target,
                    str(e.import_type),
                    e.dependency_category,
                    e.line_number or 0,
                )
            )
            result.graph.circular_dependencies.sort(
                key=lambda c: (c.length, tuple(c.modules))
            )

        # Phase 6: Deterministically sort dependency diagnostics
        if hasattr(result, 'dependency_diagnostics') and result.dependency_diagnostics:
            result.dependency_diagnostics.sort(
                key=lambda d: (
                    d.file_path,
                    d.line_number or 0,
                    d.source_module,
                )
            )

        # Phase 7: Deterministically sort component graph
        if result.graph and result.graph.component_graph:
            cg = result.graph.component_graph
            cg.nodes.sort(key=lambda n: n.id)
            cg.edges.sort(
                key=lambda e: (
                    e.source,
                    e.target,
                    tuple(sorted(e.file_edges)),
                )
            )

        # Phase 7: Deterministically sort health deductions
        if result.health:
            result.health.architecture_health.deductions.sort(
                key=lambda d: (d.rule_id, d.reason, d.points_deducted)
            )
            result.health.security_posture.deductions.sort(
                key=lambda d: (d.rule_id, d.reason, d.points_deducted)
            )

        dumped = result.model_dump(mode="json")
        return json.dumps(dumped, indent=2, sort_keys=True)
