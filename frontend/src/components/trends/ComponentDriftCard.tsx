import React from 'react';
import { ArrowDownRight, ArrowUpRight, Minus, Layers } from 'lucide-react';
import { ComponentDriftSummary } from '../../types';

interface ComponentDriftCardProps {
  drift: ComponentDriftSummary[];
}

export const ComponentDriftCard: React.FC<ComponentDriftCardProps> = ({ drift }) => {
  if (!drift || drift.length === 0) {
    return (
      <div className="bg-[#121824]/70 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
        No component drift metrics recorded across timeline.
      </div>
    );
  }

  return (
    <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="p-1.5 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight">Component Architectural Drift ΔI(c)</h3>
            <p className="text-[11px] text-slate-400">Instability drift and bottleneck centrality across codebase components</p>
          </div>
        </div>
        <span className="text-[11px] font-mono text-slate-500">
          Showing top {drift.length} components
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider font-semibold">
              <th className="py-2.5 px-3">Component</th>
              <th className="py-2.5 px-3 text-center">Baseline Instability</th>
              <th className="py-2.5 px-3 text-center">Current Instability</th>
              <th className="py-2.5 px-3 text-center">Drift ΔI</th>
              <th className="py-2.5 px-3 text-right">Betweenness Centrality</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {drift.map((c) => {
              const driftPositive = c.instability_drift > 0;
              const driftZero = c.instability_drift === 0;

              return (
                <tr key={c.component_id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2 px-3 font-sans">
                    <span className="font-semibold text-slate-200">{c.name}</span>
                    <span className="block text-[10px] text-slate-500 font-mono">{c.component_id}</span>
                  </td>
                  <td className="py-2 px-3 text-center text-slate-400">
                    {c.baseline_instability !== null && c.baseline_instability !== undefined
                      ? c.baseline_instability.toFixed(3)
                      : '—'}
                  </td>
                  <td className="py-2 px-3 text-center text-slate-200">
                    {c.current_instability.toFixed(3)}
                  </td>
                  <td className="py-2 px-3 text-center">
                    <span
                      className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                        driftZero
                          ? 'bg-slate-800/80 text-slate-400'
                          : driftPositive
                          ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60'
                          : 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60'
                      }`}
                    >
                      {driftZero ? (
                        <Minus className="w-3 h-3" />
                      ) : driftPositive ? (
                        <ArrowUpRight className="w-3 h-3" />
                      ) : (
                        <ArrowDownRight className="w-3 h-3" />
                      )}
                      <span>
                        {driftPositive ? `+${c.instability_drift.toFixed(3)}` : c.instability_drift.toFixed(3)}
                      </span>
                    </span>
                  </td>
                  <td className="py-2 px-3 text-right text-slate-300">
                    <span className={c.current_centrality >= 0.35 ? 'text-amber-400 font-bold' : ''}>
                      {c.current_centrality.toFixed(3)}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
