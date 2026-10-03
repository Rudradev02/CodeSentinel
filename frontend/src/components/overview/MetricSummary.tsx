import React, { useEffect, useState } from 'react';
import { Files, Code2, Network, Clock, Zap, CheckCircle2, RefreshCw, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { AnalysisSummaryDTO, IncrementalStatsDTO } from '../../types';

interface MetricSummaryProps {
  summary: AnalysisSummaryDTO;
  incrementalStats?: IncrementalStatsDTO | null;
}

function useCountUp(target: number, durationMs = 500, decimals = 0): string {
  const [val, setVal] = useState(target);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setVal(target);
      return;
    }

    let start: number | null = null;
    let frameId: number;
    const initial = val;

    const step = (timestamp: number) => {
      if (!start) start = timestamp;
      const progress = Math.min((timestamp - start) / durationMs, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setVal(initial + (target - initial) * ease);

      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [target]);

  return decimals > 0 ? val.toFixed(decimals) : Math.round(val).toLocaleString();
}

interface TrendIndicatorProps {
  value?: number;
  suffix?: string;
}

const TrendIndicator: React.FC<TrendIndicatorProps> = ({ value, suffix = '' }) => {
  if (value === undefined || value === null) return null;
  if (value > 0) {
    return (
      <span className="flex items-center space-x-0.5 text-[10px] font-mono text-emerald-400">
        <TrendingUp className="w-3 h-3" />
        <span>+{value}{suffix} from previous scan</span>
      </span>
    );
  }
  if (value < 0) {
    return (
      <span className="flex items-center space-x-0.5 text-[10px] font-mono text-amber-400">
        <TrendingDown className="w-3 h-3" />
        <span>{value}{suffix} from previous scan</span>
      </span>
    );
  }
  return (
    <span className="flex items-center space-x-0.5 text-[10px] font-mono text-slate-500">
      <Minus className="w-3 h-3" />
      <span>No change</span>
    </span>
  );
};

export const MetricSummary: React.FC<MetricSummaryProps> = ({ summary, incrementalStats }) => {
  const animatedFiles = useCountUp(summary.total_files, 500, 0);
  const animatedLoc = useCountUp(summary.total_loc, 600, 0);
  const animatedModules = useCountUp(summary.total_modules, 400, 0);
  const animatedDuration = useCountUp(summary.duration_seconds, 500, 3);

  // Extract incremental deltas for trend indicators
  const fileDelta = incrementalStats ? (summary.total_files - (incrementalStats.files_reused || 0)) : undefined;

  const metrics = [
    {
      label: 'Source Files',
      value: animatedFiles,
      icon: Files,
      accentColor: 'emerald',
      trend: incrementalStats ? { value: fileDelta !== undefined ? Math.abs(fileDelta) > 100 ? undefined : fileDelta : undefined } : undefined,
    },
    {
      label: 'Lines of Code',
      value: animatedLoc,
      icon: Code2,
      accentColor: 'cyan',
      trend: undefined,
    },
    {
      label: 'Modules / Components',
      value: animatedModules,
      icon: Network,
      accentColor: 'indigo',
      trend: undefined,
    },
    {
      label: 'Engine Duration',
      value: `${animatedDuration}s`,
      icon: Clock,
      accentColor: 'purple',
      trend: undefined,
    },
  ];

  const accentMap: Record<string, { bg: string; border: string; text: string; hoverBorder: string; shadow: string }> = {
    emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400', hoverBorder: 'hover:border-emerald-500/40', shadow: 'hover:shadow-[0_4px_20px_-4px_rgba(16,185,129,0.15)]' },
    cyan: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', text: 'text-cyan-400', hoverBorder: 'hover:border-cyan-500/40', shadow: 'hover:shadow-[0_4px_20px_-4px_rgba(6,182,212,0.15)]' },
    indigo: { bg: 'bg-indigo-500/10', border: 'border-indigo-500/20', text: 'text-indigo-400', hoverBorder: 'hover:border-indigo-500/40', shadow: 'hover:shadow-[0_4px_20px_-4px_rgba(99,102,241,0.15)]' },
    purple: { bg: 'bg-purple-500/10', border: 'border-purple-500/20', text: 'text-purple-400', hoverBorder: 'hover:border-purple-500/40', shadow: 'hover:shadow-[0_4px_20px_-4px_rgba(168,85,247,0.15)]' },
  };

  return (
    <div className="space-y-4">
      {/* 4 Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {metrics.map((m) => {
          const Icon = m.icon;
          const accent = accentMap[m.accentColor];
          return (
            <div
              key={m.label}
              className={`group metric-card panel p-4 flex items-center space-x-3.5 ${accent.hoverBorder} ${accent.shadow} cursor-default`}
            >
              <div className={`p-2.5 rounded-lg ${accent.bg} ${accent.border} ${accent.text} border group-hover:border-opacity-60 transition-colors shrink-0`}>
                <Icon className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-medium text-slate-400">{m.label}</p>
                <p className="text-2xl font-black text-white font-mono tracking-tight leading-tight">{m.value}</p>
                {m.trend && <TrendIndicator value={m.trend.value} />}
              </div>
            </div>
          );
        })}
      </div>

      {/* Incremental Analysis Telemetry Banner */}
      {incrementalStats && (
        <div className="panel border-amber-500/25 p-4 shadow-lg hover:border-amber-500/40 transition-all">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-sm text-white">Incremental Analysis Telemetry</span>
                  <span className="text-[10px] font-bold font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    ⚡ {incrementalStats.analysis_mode}
                  </span>
                </div>
                <p className="text-xs text-slate-400">Validated persistent layer caching with conservative invalidation</p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="text-right">
                <p className="text-slate-400 font-medium">Cache Hit Ratio</p>
                <p className="text-base font-bold text-emerald-400">{(incrementalStats.hit_ratio * 100).toFixed(1)}%</p>
              </div>
              <div className="text-right border-l border-slate-800 pl-4">
                <p className="text-slate-400 font-medium">Est. Time Saved</p>
                <p className="text-base font-bold text-cyan-400">{incrementalStats.estimated_time_saved_seconds.toFixed(2)}s</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-xs font-mono">
            <div className="flex items-center space-x-2 text-slate-300">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Reused: <strong className="text-white">{incrementalStats.files_reused}</strong> / {incrementalStats.files_discovered}</span>
            </div>
            <div className="flex items-center space-x-2 text-slate-300">
              <RefreshCw className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span>Re-analyzed: <strong className="text-white">{incrementalStats.files_reanalyzed}</strong></span>
            </div>
            <div className="text-slate-400">
              <span>L2 AST: <strong className="text-slate-200">{incrementalStats.ast_hits}</strong> | L4 CFG: <strong className="text-slate-200">{incrementalStats.cfg_hits}</strong></span>
            </div>
            <div className="text-slate-400">
              <span>L7 Contracts: <strong className="text-slate-200">{incrementalStats.contract_hits}</strong> | L9 Findings: <strong className="text-slate-200">{incrementalStats.finding_hits}</strong></span>
            </div>
          </div>

          {incrementalStats.invalidations_by_reason && Object.keys(incrementalStats.invalidations_by_reason).length > 0 && (
            <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
              <span className="text-[11px] text-slate-400 font-medium font-sans">Invalidation Reasons:</span>
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


