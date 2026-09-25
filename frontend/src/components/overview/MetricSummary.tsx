import React from 'react';
import { Files, Code2, Network, Clock, Zap, CheckCircle2, RefreshCw } from 'lucide-react';
import { AnalysisSummaryDTO, IncrementalStatsDTO } from '../../types';

interface MetricSummaryProps {
  summary: AnalysisSummaryDTO;
  incrementalStats?: IncrementalStatsDTO | null;
}

export const MetricSummary: React.FC<MetricSummaryProps> = ({ summary, incrementalStats }) => {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-[#121824]/80 border border-slate-800/80 rounded-xl p-4 flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Files className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">Source Files</p>
            <p className="text-xl font-bold text-white tracking-tight">{summary.total_files.toLocaleString()}</p>
          </div>
        </div>

        <div className="bg-[#121824]/80 border border-slate-800/80 rounded-xl p-4 flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Code2 className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">Lines of Code</p>
            <p className="text-xl font-bold text-white tracking-tight">{summary.total_loc.toLocaleString()}</p>
          </div>
        </div>

        <div className="bg-[#121824]/80 border border-slate-800/80 rounded-xl p-4 flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">Modules / Components</p>
            <p className="text-xl font-bold text-white tracking-tight">{summary.total_modules}</p>
          </div>
        </div>

        <div className="bg-[#121824]/80 border border-slate-800/80 rounded-xl p-4 flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">Engine Duration</p>
            <p className="text-xl font-bold text-white tracking-tight">{summary.duration_seconds.toFixed(3)}s</p>
          </div>
        </div>
      </div>

      {incrementalStats && (
        <div className="bg-[#121824]/90 border border-amber-500/20 rounded-xl p-4 shadow-lg shadow-amber-950/10">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-sm text-white">Incremental Analysis Telemetry</span>
                  <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    ⚡ {incrementalStats.analysis_mode}
                  </span>
                </div>
                <p className="text-xs text-slate-400">Validated persistent layer caching with conservative invalidation</p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <div className="text-right">
                <p className="text-slate-400 font-medium">Cache Hit Ratio</p>
                <p className="text-sm font-bold text-emerald-400">{(incrementalStats.hit_ratio * 100).toFixed(1)}%</p>
              </div>
              <div className="text-right border-l border-slate-800 pl-4">
                <p className="text-slate-400 font-medium">Estimated Time Saved</p>
                <p className="text-sm font-bold text-cyan-400">{incrementalStats.estimated_time_saved_seconds.toFixed(2)}s</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-xs">
            <div className="flex items-center space-x-2 text-slate-300">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Reused Files: <strong className="text-white">{incrementalStats.files_reused}</strong> / {incrementalStats.files_discovered}</span>
            </div>
            <div className="flex items-center space-x-2 text-slate-300">
              <RefreshCw className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span>Re-analyzed: <strong className="text-white">{incrementalStats.files_reanalyzed}</strong> files</span>
            </div>
            <div className="text-slate-400">
              <span>L2 AST Hits: <strong className="text-slate-200">{incrementalStats.ast_hits}</strong> | L4 CFG: <strong className="text-slate-200">{incrementalStats.cfg_hits}</strong></span>
            </div>
            <div className="text-slate-400">
              <span>L7 Contracts: <strong className="text-slate-200">{incrementalStats.contract_hits}</strong> | L9 Findings: <strong className="text-slate-200">{incrementalStats.finding_hits}</strong></span>
            </div>
          </div>

          {incrementalStats.invalidations_by_reason && Object.keys(incrementalStats.invalidations_by_reason).length > 0 && (
            <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
              <span className="text-[11px] text-slate-400 font-medium">Invalidation Reasons:</span>
              {Object.entries(incrementalStats.invalidations_by_reason).map(([reason, count]) => (
                <span
                  key={reason}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60"
                  title={`${count} file(s) invalidated due to ${reason}`}
                >
                  {reason}: {count}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

