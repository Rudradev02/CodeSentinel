import ast
import json
from typing import Optional

from analyzer.models.errors import AnalysisCancelledError
from analyzer.models.findings import EvidenceType, Finding, FindingSeverity
from analyzer.models.graph import ArchitectureGraph
from analyzer.models.metadata import DiscoveredFileMetadata
from analyzer.models.parse import ParsedFile
from analyzer.models.results import ArchitectureSummary, SecuritySummary
from analyzer.rules.registry import RuleRegistry


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministically deduplicate findings based on rule_id, file, line, column, and normalized evidence.
    
    Preserves distinct findings on the same line if they represent different evidence or column offsets.
    Maintains deterministic order.
    """
    seen: set[tuple[str, str, int, int, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        col = f.location.col_start if f.location.col_start is not None else 0
        norm_ev = json.dumps(f.evidence, sort_keys=True, default=str) if f.evidence else f.code_snippet
        key = (f.rule_id, f.location.file_path, f.location.line_start, col, norm_ev)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort findings strictly deterministically: file_path -> line_start -> col_start -> rule_id -> normalized_evidence
    deduped.sort(
        key=lambda f: (
            f.location.file_path,
            f.location.line_start,
            f.location.col_start or 0,
            f.rule_id,
            json.dumps(f.evidence, sort_keys=True, default=str) if f.evidence else f.code_snippet,
        )
    )
    return deduped


class RuleEngine:
    """Orchestrates deterministic and heuristic rule execution over parsed codebase artifacts."""

    def __init__(self, registry: Optional[RuleRegistry] = None, config: Optional[Any] = None):
        self.registry = registry or RuleRegistry(load_defaults=True)
        self.config = config

    def analyze_security(
        self,
        files: list[DiscoveredFileMetadata],
        file_contents: dict[str, str],
        parsed_files: list[ParsedFile],
        detected_frameworks: list[str],
        interprocedural_paths: Optional[list[Any]] = None,
    ) -> tuple[list[Finding], SecuritySummary]:
        """Execute applicable security rules across discovered source files.
        
        Args:
            files: Metadata for discovered files.
            file_contents: Mapping of repository-relative path to raw source content.
            parsed_files: Normalized parsed file representations from Phase 2.
            detected_frameworks: List of repository-level detected framework names.
            interprocedural_paths: Optional list of precomputed InterproceduralTaintPath objects.
            
        Returns:
            Tuple of (deterministically deduplicated and sorted findings, aggregated SecuritySummary).
        """
        all_findings: list[Finding] = []

        # Pre-parse Python ASTs once where applicable to avoid redundant parsing per rule
        ast_cache: dict[str, Optional[ast.AST]] = {}

        for f in files:
            rel = f.relative_path.replace("\\", "/")
            content = file_contents.get(rel, "")
            if not content:
                continue

            rules = self.registry.get_applicable_security_rules(
                language=f.language,
                detected_frameworks=detected_frameworks,
            )
            if not rules:
                continue

            pre_parsed_ast = None
            if f.language == "PYTHON":
                if rel not in ast_cache:
                    try:
                        ast_cache[rel] = ast.parse(content, filename=rel)
                    except Exception:
                        ast_cache[rel] = None
                pre_parsed_ast = ast_cache[rel]

            for rule in rules:
                try:
                    findings = rule.analyze(
                        file_path=rel,
                        content=content,
                        ast_node=pre_parsed_ast,
                        detected_frameworks=detected_frameworks,
                        interprocedural_paths=interprocedural_paths,
                    )
                    all_findings.extend(findings)
                except AnalysisCancelledError:
                    raise
                except Exception:
                    # Individual rule exceptions must not crash the engine
                    pass

        # Phase 22: Populate structured security evidence chains
        enable_chains = getattr(self.config, "enable_evidence_chains", True) if self.config else True
        max_depth = getattr(self.config, "max_evidence_chain_depth", 10) if self.config else 10
        if enable_chains:
            from analyzer.models.evidence import build_security_evidence_chain_from_path
            for finding in all_findings:
                if finding.evidence and ("call_chain" in finding.evidence or finding.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT"):
                    if "security_chain" not in finding.evidence:
                        chain = build_security_evidence_chain_from_path(finding.evidence, max_depth=max_depth)
                        finding.evidence["security_chain"] = chain.model_dump(mode="json")

        # Deterministically deduplicate findings
        final_findings = deduplicate_findings(all_findings)

        # Aggregate summary metrics
        summary = SecuritySummary(
            total=len(final_findings),
            critical=sum(1 for f in final_findings if f.severity == FindingSeverity.CRITICAL),
            high=sum(1 for f in final_findings if f.severity == FindingSeverity.HIGH),
            medium=sum(1 for f in final_findings if f.severity == FindingSeverity.MEDIUM),
            low=sum(1 for f in final_findings if f.severity == FindingSeverity.LOW),
            info=sum(1 for f in final_findings if f.severity == FindingSeverity.INFO),
            deterministic_count=sum(
                1 for f in final_findings if f.evidence_type == EvidenceType.DETERMINISTIC
            ),
            heuristic_count=sum(
                1 for f in final_findings if f.evidence_type == EvidenceType.HEURISTIC
            ),
            ai_enriched_count=0,
        )

        return final_findings, summary

    def analyze_architecture(
        self,
        graph: ArchitectureGraph,
        parsed_files: Optional[list[ParsedFile]] = None,
    ) -> tuple[list[Finding], ArchitectureSummary]:
        """Execute architecture smell rules over the dependency graph.
        
        Args:
            graph: Constructed ArchitectureGraph with coupling metrics and optional component graph.
            parsed_files: Optional list of ParsedFiles for rules requiring AST symbol context (e.g. ARC-008).
            
        Returns:
            Tuple of (deterministically deduplicated and sorted findings, aggregated ArchitectureSummary).
        """
        all_findings: list[Finding] = []
        rules = self.registry.get_all_architecture_rules()

        for rule in rules:
            try:
                try:
                    findings = rule.analyze(graph, parsed_files=parsed_files)
                except TypeError:
                    findings = rule.analyze(graph)
                all_findings.extend(findings)
            except AnalysisCancelledError:
                raise
            except Exception:
                pass

        # Deterministically deduplicate findings
        final_findings = deduplicate_findings(all_findings)

        # Count god modules identified on the graph
        god_modules_count = sum(1 for n in graph.nodes if n.is_god_module)

        summary = ArchitectureSummary(
            total_modules=graph.metrics.total_modules,
            circular_dependencies_count=graph.metrics.circular_cycles_count,
            god_modules_count=god_modules_count,
            total_findings=len(final_findings),
        )

        return final_findings, summary

