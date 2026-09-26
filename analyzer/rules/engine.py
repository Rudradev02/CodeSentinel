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

        # Phase 23: Framework trust boundary extraction
        enable_boundaries = getattr(self.config, "enable_boundary_detection", True) if self.config else True
        enable_policies = getattr(self.config, "enable_policy_engine", True) if self.config else True
        policy_mode = getattr(self.config, "policy_mode", "ENFORCE") if self.config else "ENFORCE"

        trust_boundaries: list[Any] = []
        if enable_boundaries:
            from analyzer.frameworks.base import FrameworkModelRegistry
            fw_reg = FrameworkModelRegistry(load_defaults=True)
            applicable_adapters = fw_reg.get_applicable_adapters(detected_frameworks or [])
            parsed_by_path = {}
            for pf in parsed_files:
                if hasattr(pf, "relative_path") and pf.relative_path:
                    parsed_by_path[pf.relative_path.replace("\\", "/").lstrip("./")] = pf
                if hasattr(pf, "file_path") and pf.file_path:
                    parsed_by_path[pf.file_path.replace("\\", "/").lstrip("./")] = pf
            for f in files:
                rel = f.relative_path.replace("\\", "/").lstrip("./")
                content = file_contents.get(rel, "")
                parsed_f = parsed_by_path.get(rel) or ParsedFile(
                    file_path=getattr(f, "path", rel),
                    relative_path=rel,
                    language=f.language,
                    symbols=[],
                    errors=[],
                )
                tree = ast_cache.get(rel)
                for adapter in applicable_adapters:
                    try:
                        b_list = adapter.extract_trust_boundaries(parsed_f, ast_tree=tree, file_content=content)
                        trust_boundaries.extend(b_list)
                    except Exception:
                        pass

        # Phase 23: Policy evaluation & finding enrichment
        if enable_policies and policy_mode != "DISABLED":
            from analyzer.rules.policy import SecurityPolicyRegistry, PolicyEvaluationResult
            from analyzer.dataflow.properties import SecurityPropertyState
            from analyzer.dataflow.taint.models import SinkCategory
            from analyzer.models.boundary import AuthenticationState, AuthorizationState
            from analyzer.models.evidence import PolicyEvaluationEvidence

            policy_reg = SecurityPolicyRegistry(load_defaults=True)
            filtered_findings = []
            for finding in all_findings:
                sink_cat = None
                if finding.evidence:
                    cat_val = finding.evidence.get("category")
                    if cat_val:
                        try:
                            sink_cat = SinkCategory(cat_val)
                        except Exception:
                            pass

                sanitizer_data = finding.evidence.get("sanitizer") if finding.evidence else None
                sanitizer_id = sanitizer_data.get("sanitizer_id") if sanitizer_data else None

                matched_boundary = None
                src_data = finding.evidence.get("source") if finding.evidence else None
                if src_data and trust_boundaries:
                    src_file = str(src_data.get("file_path", "")).replace("\\", "/").lstrip("./")
                    src_line = int(src_data.get("line", 0))
                    for b in trust_boundaries:
                        b_file = b.file_path.replace("\\", "/").lstrip("./")
                        if b_file == src_file and abs(b.line - src_line) <= 2:
                            matched_boundary = b
                            break

                policies = policy_reg.get_applicable_policies(
                    boundary_type=matched_boundary.boundary_type if matched_boundary else None,
                    sink_category=sink_cat,
                    rule_id=finding.rule_id,
                )

                if policies:
                    policy = policies[0]
                    prop_state = SecurityPropertyState()
                    if sanitizer_id:
                        san_lower = sanitizer_id.lower()
                        if "int" in san_lower or "integer" in san_lower or "parseint" in san_lower:
                            prop_state.add_property(SecurityProperty.TYPE_COERCED)
                            prop_state.add_property(SecurityProperty.SQL_SAFE)
                            prop_state.add_property(SecurityProperty.VALIDATED_TYPE)
                        elif "float" in san_lower or "parsefloat" in san_lower or "number" in san_lower:
                            prop_state.add_property(SecurityProperty.TYPE_COERCED)
                            prop_state.add_property(SecurityProperty.SQL_SAFE)
                            prop_state.add_property(SecurityProperty.VALIDATED_TYPE)
                        elif "shlex" in san_lower or "shell_escape" in san_lower or "quote" in san_lower:
                            prop_state.add_property(SecurityProperty.COMMAND_SAFE)
                            prop_state.add_property(SecurityProperty.SHELL_QUOTED)
                        elif "dompurify" in san_lower or "escape" in san_lower or "html" in san_lower:
                            prop_state.add_property(SecurityProperty.HTML_ESCAPED)
                        elif "path" in san_lower or "basename" in san_lower:
                            prop_state.add_property(SecurityProperty.PATH_NORMALIZED)
                            prop_state.add_property(SecurityProperty.PATH_SAFE)

                    call_chain = finding.evidence.get("call_chain", []) if finding.evidence else []
                    for step in call_chain:
                        step_expr = step.get("expression") or step.get("symbol") or ""
                        if step_expr:
                            prop_state = prop_state.derive_from_expression(step_expr)

                    auth_st = matched_boundary.is_authenticated if matched_boundary else AuthenticationState.UNKNOWN
                    authz_st = matched_boundary.is_authorized if matched_boundary else AuthorizationState.UNKNOWN

                    outcome = policy.evaluate(
                        sink_category=sink_cat,
                        property_state=prop_state,
                        auth_state=auth_st,
                        authz_state=authz_st,
                        sanitizer_id=sanitizer_id,
                    )
                    eval_result = outcome.result
                    satisfied = outcome.satisfied_properties
                    missing = outcome.missing_properties
                    details = outcome.explanation

                    pol_ev = PolicyEvaluationEvidence(
                        policy_id=policy.policy_id,
                        policy_name=policy.name,
                        evaluation_result=eval_result.value,
                        satisfied_properties=satisfied,
                        missing_properties=missing,
                        details=details,
                    )

                    if policy_mode == "ENFORCE" and eval_result == PolicyEvaluationResult.PROVEN_SAFE:
                        continue

                    if finding.evidence is not None:
                        finding.evidence["policy_evaluation"] = pol_ev.model_dump(mode="json")
                        if matched_boundary:
                            finding.evidence["trust_boundary"] = matched_boundary.model_dump(mode="json")
                        enable_obligations = getattr(self.config, "enable_proof_obligations", True) if self.config else True
                        if enable_obligations:
                            finding.evidence["proof_obligations"] = [
                                o.model_dump(mode="json") for o in outcome.proof_obligations
                            ]
                            finding.evidence["unknown_reasons"] = list(outcome.unknown_reasons)

                filtered_findings.append(finding)
            all_findings = filtered_findings

        # Phase 22, Phase 23 & Phase 24: Populate structured security evidence chains
        enable_chains = getattr(self.config, "enable_evidence_chains", True) if self.config else True
        max_depth = getattr(self.config, "max_evidence_chain_depth", 10) if self.config else 10
        if enable_chains:
            from analyzer.models.evidence import (
                build_security_evidence_chain_from_path,
                PolicyEvaluationEvidence,
            )
            for finding in all_findings:
                if finding.evidence and ("call_chain" in finding.evidence or finding.evidence.get("flow_type") == "INTER_PROCEDURAL_TAINT"):
                    if "security_chain" not in finding.evidence:
                        pol_raw = finding.evidence.get("policy_evaluation")
                        pol_ev = PolicyEvaluationEvidence.model_validate(pol_raw) if pol_raw else None
                        tb_raw = finding.evidence.get("trust_boundary")
                        p_obs = finding.evidence.get("proof_obligations")
                        u_rsns = finding.evidence.get("unknown_reasons")
                        chain = build_security_evidence_chain_from_path(
                            finding.evidence,
                            max_depth=max_depth,
                            trust_boundary=tb_raw,
                            policy_evaluation=pol_ev,
                            proof_obligations=p_obs,
                            unknown_reasons=u_rsns,
                        )
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

