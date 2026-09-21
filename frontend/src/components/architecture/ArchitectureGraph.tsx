import React, { useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network, RefreshCcw, Info } from 'lucide-react';
import { ComponentGraphDTO, ComponentNodeDTO } from '../../types';

interface ArchitectureGraphProps {
  graph?: ComponentGraphDTO | null;
}

// Canonical layer ordering for visual layering
const LAYER_ORDER: Record<string, number> = {
  PRESENTATION: 0,
  APPLICATION: 1,
  DOMAIN: 2,
  INFRASTRUCTURE: 3,
  UTILITY: 4,
};

function getLayerBadgeColor(layer?: string | null): string {
  switch (layer?.toUpperCase()) {
    case 'PRESENTATION':
      return 'bg-purple-950/80 text-purple-300 border-purple-800/80';
    case 'APPLICATION':
      return 'bg-blue-950/80 text-blue-300 border-blue-800/80';
    case 'DOMAIN':
      return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80';
    case 'INFRASTRUCTURE':
      return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
    case 'UTILITY':
      return 'bg-slate-800 text-slate-300 border-slate-700';
    default:
      return 'bg-slate-800/80 text-slate-400 border-slate-700/60';
  }
}

export const ArchitectureGraph: React.FC<ArchitectureGraphProps> = ({ graph }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Derive React Flow nodes and edges
  const { nodes, edges } = useMemo(() => {
    if (!graph || !graph.nodes || graph.nodes.length === 0) {
      return { nodes: [], edges: [] };
    }

    // Group nodes by layer for column/row layout
    const layerBuckets: Record<string, ComponentNodeDTO[]> = {};
    const unlayered: ComponentNodeDTO[] = [];

    graph.nodes.forEach((node) => {
      const l = node.layer?.toUpperCase();
      if (l && l in LAYER_ORDER) {
        if (!layerBuckets[l]) layerBuckets[l] = [];
        layerBuckets[l].push(node);
      } else {
        unlayered.push(node);
      }
    });

    const flowNodes: Node[] = [];
    const COL_WIDTH = 280;
    const ROW_HEIGHT = 160;

    let colIndex = 0;
    const orderedLayers = ['PRESENTATION', 'APPLICATION', 'DOMAIN', 'INFRASTRUCTURE', 'UTILITY'];

    orderedLayers.forEach((layerKey) => {
      const bucket = layerBuckets[layerKey];
      if (bucket && bucket.length > 0) {
        bucket.forEach((node, rowIndex) => {
          flowNodes.push({
            id: node.id,
            position: {
              x: colIndex * COL_WIDTH + 60,
              y: rowIndex * ROW_HEIGHT + 80,
            },
            data: {
              component: node,
              label: node.name,
            },
            style: {
              background: '#121824',
              color: '#F1F5F9',
              border: selectedNodeId === node.id ? '2px solid #10B981' : '1px solid #334155',
              borderRadius: '12px',
              padding: '12px',
              width: 240,
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.4)',
            },
          });
        });
        colIndex++;
      }
    });

    // Place remaining unassigned components in subsequent columns
    unlayered.forEach((node, idx) => {
      const col = colIndex + Math.floor(idx / 4);
      const row = idx % 4;
      flowNodes.push({
        id: node.id,
        position: {
          x: col * COL_WIDTH + 60,
          y: row * ROW_HEIGHT + 80,
        },
        data: {
          component: node,
          label: node.name,
        },
        style: {
          background: '#121824',
          color: '#F1F5F9',
          border: selectedNodeId === node.id ? '2px solid #10B981' : '1px solid #334155',
          borderRadius: '12px',
          padding: '12px',
          width: 240,
          boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.4)',
        },
      });
    });

    // Create edges
    const flowEdges: Edge[] = graph.edges.map((e) => {
      const isCycle = e.is_cycle;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: isCycle,
        style: {
          stroke: isCycle ? '#F43F5E' : '#64748B',
          strokeWidth: isCycle ? 2.5 : 1.5,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isCycle ? '#F43F5E' : '#64748B',
          width: 14,
          height: 14,
        },
        label: e.weight > 1 ? `${e.weight}x` : undefined,
        labelStyle: { fill: '#94A3B8', fontSize: 10, fontFamily: 'monospace' },
        labelBgStyle: { fill: '#0E1420', fillOpacity: 0.8 },
      };
    });

    return { nodes: flowNodes, edges: flowEdges };
  }, [graph, selectedNodeId]);

  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !graph?.nodes) return null;
    return graph.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [graph, selectedNodeId]);

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div className="bg-[#121824]/60 border border-slate-800 rounded-xl p-16 text-center space-y-2">
        <Network className="w-10 h-10 text-slate-500 mx-auto" />
        <h3 className="text-sm font-semibold text-slate-200">No Component Graph Data Available</h3>
        <p className="text-xs text-slate-500 max-w-sm mx-auto">
          Run analysis on a multi-file repository with directory structure to view subsystem component coupling.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Graph Summary Header */}
      <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <span>Subsystem Component Graph</span>
              <span className="text-xs font-normal text-slate-400">
                ({graph.nodes.length} components, {graph.edges.length} edges)
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Robert C. Martin Coupling: Ca (Afferent), Ce (Efferent), I (Instability)
            </p>
          </div>
        </div>

        {/* Cycle indicator */}
        <div className="flex items-center space-x-2">
          {graph.circular_components_count > 0 ? (
            <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold bg-rose-950/80 text-rose-300 border border-rose-800/80">
              <RefreshCcw className="w-3.5 h-3.5 animate-spin" />
              <span>{graph.circular_components_count} Component Cycle(s) Detected</span>
            </span>
          ) : (
            <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80">
              <span>Acyclic Subsystems (Zero Cycles)</span>
            </span>
          )}
        </div>
      </div>

      {/* Main Canvas Container */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Canvas */}
        <div className="lg:col-span-9 h-[620px] bg-[#0A0E17] border border-slate-800 rounded-xl overflow-hidden relative shadow-inner">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            onPaneClick={() => setSelectedNodeId(null)}
            fitView
            minZoom={0.2}
            maxZoom={1.8}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#1E293B" />
            <Controls className="bg-[#121824] border border-slate-700 fill-slate-300 text-slate-300" />
            <MiniMap
              nodeStrokeColor="#10B981"
              nodeColor="#1E293B"
              maskColor="rgba(10, 14, 23, 0.8)"
              className="bg-[#0B0F17] border border-slate-800 rounded-lg overflow-hidden"
            />
          </ReactFlow>
        </div>

        {/* Selected Component Metrics Side Drawer */}
        <div className="lg:col-span-3 bg-[#121824]/90 border border-slate-800 rounded-xl p-4.5 space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center space-x-2">
            <Info className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Component Inspector
            </h4>
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <p className="text-[10px] text-slate-400 font-bold uppercase">Component ID</p>
                <p className="font-mono font-bold text-emerald-400 mt-0.5 break-all">{selectedNode.id}</p>
                <p className="font-mono text-slate-400 text-[11px] mt-0.5">{selectedNode.path}</p>
              </div>

              {selectedNode.layer && (
                <div>
                  <p className="text-[10px] text-slate-400 font-bold uppercase">Inferred Layer</p>
                  <span
                    className={`inline-flex px-2 py-0.5 rounded text-xs font-bold border mt-1 ${getLayerBadgeColor(
                      selectedNode.layer
                    )}`}
                  >
                    {selectedNode.layer}
                  </span>
                </div>
              )}

              {/* Coupling Stats */}
              <div className="space-y-2 pt-2 border-t border-slate-800/60">
                <p className="text-[10px] text-slate-400 font-bold uppercase">Coupling & Stability</p>
                <div className="grid grid-cols-2 gap-2 font-mono">
                  <div className="bg-[#0B0F17] p-2 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px]">Ca (Afferent)</span>
                    <p className="text-sm font-bold text-white">{selectedNode.coupling.afferent}</p>
                  </div>
                  <div className="bg-[#0B0F17] p-2 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px]">Ce (Efferent)</span>
                    <p className="text-sm font-bold text-white">{selectedNode.coupling.efferent}</p>
                  </div>
                </div>

                <div className="bg-[#0B0F17] p-2.5 rounded border border-slate-800 space-y-1.5">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400 font-mono">Instability (I)</span>
                    <span className="font-bold text-white font-mono">
                      {selectedNode.coupling.instability.toFixed(2)}
                    </span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500"
                      style={{ width: `${selectedNode.coupling.instability * 100}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[9px] text-slate-500">
                    <span>0.0 (Stable)</span>
                    <span>1.0 (Volatile)</span>
                  </div>
                </div>
              </div>

              {/* Files in Component */}
              <div className="space-y-1 pt-2 border-t border-slate-800/60">
                <p className="text-[10px] text-slate-400 font-bold uppercase">
                  Files ({selectedNode.files.length})
                </p>
                <div className="max-h-40 overflow-y-auto space-y-1 pr-1 font-mono text-[11px] text-slate-400">
                  {selectedNode.files.map((file) => (
                    <div key={file} className="truncate bg-[#0B0F17]/60 px-2 py-1 rounded border border-slate-800/40">
                      {file}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500 space-y-1">
              <p>Click any component node in the canvas to view its coupling metrics and files.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
