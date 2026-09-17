"""ARC-004: Deep Dependency Chain Anti-Pattern."""

import networkx as nx

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.models.findings import (
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingSeverity,
    SourceLocation,
)
from analyzer.models.graph import ArchitectureGraph

DEFAULT_DEPTH_THRESHOLD = 5


class RuleArc004(BaseArchitectureRule):
    """ARC-004: Deep Dependency Chain.
    
    Safe DAG condensation approach:
    1. Filter the local (intra-repository) dependency graph.
    2. Condense strongly connected components (SCCs) via nx.condensation() into a guaranteed DAG.
    3. Calculate the longest path through the condensed DAG via nx.dag_longest_path().
    4. Map condensed component nodes back to representative local modules.
    5. Evaluate if the resulting transitive dependency hop count exceeds the configured threshold.
    """

    rule_id = "ARC-004"
    name = "Deep Dependency Chain"
    evidence_type = EvidenceType.HEURISTIC
    severity = FindingSeverity.LOW
    confidence = FindingConfidence.MEDIUM
    description = (
        "Detected an unusually deep transitive dependency chain across modules. "
        "Excessive architectural layering (chains exceeding 5 hops) increases structural rigidity, "
        "makes changes difficult to reason about, and magnifies initialization latency."
    )
    rationale = (
        "Excessively deep dependency chains increase structural rigidity, prolong module initialization time, "
        "and make cascading side effects difficult to predict."
    )
    remediation = (
        "Flatten the dependency hierarchy by introducing domain boundaries, event-driven decoupling, "
        "or direct dependency inversion where lower layers do not propagate through multiple intermediaries."
    )

    def __init__(self, depth_threshold: int = DEFAULT_DEPTH_THRESHOLD):
        self.depth_threshold = depth_threshold

    def analyze(self, graph: ArchitectureGraph) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Build local directed graph
        local_node_ids = {n.id for n in graph.nodes if not n.is_external}
        if len(local_node_ids) < 2:
            return []

        local_digraph = nx.DiGraph()
        for node_id in local_node_ids:
            local_digraph.add_node(node_id)

        for edge in graph.edges:
            if edge.source in local_node_ids and edge.target in local_node_ids:
                local_digraph.add_edge(edge.source, edge.target)

        if local_digraph.number_of_edges() == 0:
            return []

        try:
            # 2. Safely condense SCCs into a DAG to handle any cycles without infinite loops or recursion errors
            condensed_dag = nx.condensation(local_digraph)

            # 3. Calculate longest path on the guaranteed DAG
            longest_component_path = nx.dag_longest_path(condensed_dag)

            # 4. Map components back to representative modules in deterministic order
            chain_modules: list[str] = []
            for comp_id in longest_component_path:
                members = sorted(list(condensed_dag.nodes[comp_id]["members"]))
                if members:
                    chain_modules.append(members[0])

            # Depth is the number of edges/hops in the chain
            depth = len(chain_modules) - 1

            # 5. Check against threshold
            if depth > self.depth_threshold:
                first_module = chain_modules[0]
                chain_str = " -> ".join(chain_modules)

                location = SourceLocation(
                    file_path=first_module,
                    line_start=1,
                    line_end=1,
                    col_start=0,
                    col_end=None,
                )

                snippet = f"// Deep dependency chain (depth: {depth}, threshold: > {self.depth_threshold}):\n{chain_str}"
                evidence = {
                    "depth": depth,
                    "threshold": self.depth_threshold,
                    "longest_path": chain_modules,
                    "chain": chain_str,
                }
                findings.append(
                    self.create_finding(
                        location=location,
                        code_snippet=snippet,
                        custom_description=(
                            f"Deep transitive dependency chain detected: [{chain_str}] spanning {depth} hops "
                            f"(threshold: > {self.depth_threshold}). Calculated via SCC-condensed DAG analysis. "
                            "Deep dependency chains increase structural coupling and propagation of breaking changes."
                        ),
                        message=f"Deep transitive dependency chain (depth: {depth})",
                        explanation=(
                            f"Deep transitive dependency chain detected: [{chain_str}] spanning {depth} hops "
                            f"(threshold: > {self.depth_threshold}). Calculated via SCC-condensed DAG analysis. "
                            "Deep dependency chains increase structural coupling and propagation of breaking changes."
                        ),
                        evidence=evidence,
                    )
                )
        except Exception:
            # Safe degradation if graph cannot be analyzed
            pass

        return findings
