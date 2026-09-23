"""Repository-local component graph centrality metrics calculator."""

import networkx as nx

from analyzer.models.graph import ComponentGraph


class CentralityCalculator:
    """Computes Betweenness, In-Degree, and Out-Degree centrality over local ComponentGraph."""

    @classmethod
    def compute(cls, component_graph: ComponentGraph) -> ComponentGraph:
        """Calculate and attach centrality metrics to all component nodes.
        
        Guarantees:
        - Strictly repository-local: External libraries and unresolved imports are excluded.
        - Deterministic rounding: All floats rounded to 4 decimal places.
        - Robust on isolated nodes, self-loops, and cycles.
        """
        if not component_graph.nodes:
            return component_graph

        # Build directed NetworkX graph
        G = nx.DiGraph()
        for node in component_graph.nodes:
            G.add_node(node.id)

        for edge in component_graph.edges:
            G.add_edge(edge.source, edge.target, weight=edge.weight)

        num_nodes = len(G.nodes)

        if num_nodes <= 1:
            # Trivial graph: centrality is zero
            for node in component_graph.nodes:
                node.metrics.betweenness_centrality = 0.0
                node.metrics.in_degree_centrality = 0.0
                node.metrics.out_degree_centrality = 0.0
            return component_graph

        # 1. Betweenness Centrality (normalized by default in nx for directed graphs)
        try:
            betweenness = nx.betweenness_centrality(G, normalized=True)
        except Exception:
            betweenness = {n: 0.0 for n in G.nodes}

        # 2. In-Degree Centrality (normalized: deg_in / (N - 1))
        try:
            in_degree = nx.in_degree_centrality(G)
        except Exception:
            in_degree = {n: 0.0 for n in G.nodes}

        # 3. Out-Degree Centrality (normalized: deg_out / (N - 1))
        try:
            out_degree = nx.out_degree_centrality(G)
        except Exception:
            out_degree = {n: 0.0 for n in G.nodes}

        # Update each ComponentNode metrics
        for node in component_graph.nodes:
            node.metrics.betweenness_centrality = round(betweenness.get(node.id, 0.0), 4)
            node.metrics.in_degree_centrality = round(in_degree.get(node.id, 0.0), 4)
            node.metrics.out_degree_centrality = round(out_degree.get(node.id, 0.0), 4)

        return component_graph
