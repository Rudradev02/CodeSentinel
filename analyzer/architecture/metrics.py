"""Calculation of architectural coupling metrics and circular dependency cycle detection."""

import networkx as nx

from analyzer.models.graph import (
    ArchitectureGraph,
    CircularDependency,
    CouplingMetrics,
    DependencyEdge,
    DependencyNode,
)


class ArchitectureMetricsCalculator:
    """Calculates fan-in, fan-out, coupling density, and detects circular dependency cycles."""

    @staticmethod
    def compute(
        G: nx.DiGraph,
        nodes: list[DependencyNode],
        edges: list[DependencyEdge],
    ) -> ArchitectureGraph:
        """Compute structural metrics and cycle annotations over the dependency graph.
        
        Phase 2 calculates metrics only and detects circular dependencies.
        It intentionally does NOT classify god modules or architectural smells (Phase 3).
        """
        # 1. Filter local subgraph for intra-repository dependency metrics
        local_node_ids = {n.id for n in nodes if not n.is_external}
        local_subgraph = G.subgraph(local_node_ids).copy()

        # 2. Cycle Detection on local module graph
        circular_dependencies: list[CircularDependency] = []
        cycle_edges_set = set()

        try:
            cycles = list(nx.simple_cycles(local_subgraph))
            for cycle in cycles:
                if len(cycle) >= 2:
                    circular_dependencies.append(
                        CircularDependency(
                            modules=cycle,
                            length=len(cycle),
                        )
                    )
                    # Record participating edges
                    for i in range(len(cycle)):
                        u = cycle[i]
                        v = cycle[(i + 1) % len(cycle)]
                        cycle_edges_set.add((u, v))
        except Exception:
            # Fallback if graph is too complex for simple_cycles
            pass

        # 3. Mark edges participating in circular dependencies
        for edge in edges:
            if (edge.source, edge.target) in cycle_edges_set:
                edge.is_circular = True

        # 4. Compute per-node metrics
        for node in nodes:
            if node.id in local_subgraph:
                node.fan_in = local_subgraph.in_degree(node.id)
                node.fan_out = local_subgraph.out_degree(node.id)
                node.dependencies_count = G.out_degree(node.id) if node.id in G else 0
                node.dependents_count = node.fan_in

        # 5. Compute aggregate CouplingMetrics
        total_modules = len(local_node_ids)
        total_local_edges = local_subgraph.number_of_edges()

        density = 0.0
        if total_modules > 1:
            try:
                density = round(float(nx.density(local_subgraph)), 4)
            except Exception:
                density = 0.0

        fan_ins = [n.fan_in for n in nodes if not n.is_external]
        fan_outs = [n.fan_out for n in nodes if not n.is_external]

        avg_fan_in = round(sum(fan_ins) / total_modules, 2) if total_modules > 0 else 0.0
        avg_fan_out = round(sum(fan_outs) / total_modules, 2) if total_modules > 0 else 0.0
        max_fan_out = max(fan_outs) if fan_outs else 0

        coupling_metrics = CouplingMetrics(
            total_modules=total_modules,
            total_edges=total_local_edges,
            density=density,
            average_fan_in=avg_fan_in,
            average_fan_out=avg_fan_out,
            max_fan_out=max_fan_out,
            circular_cycles_count=len(circular_dependencies),
        )

        return ArchitectureGraph(
            nodes=nodes,
            edges=edges,
            circular_dependencies=circular_dependencies,
            metrics=coupling_metrics,
        )
