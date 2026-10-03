import React from 'react';
import { ShieldCheck, XCircle, Check, Loader2, Circle } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  targetPath?: string;
  progressPercent?: number;
  stage?: string | null;
  onCancel?: () => void;
}

interface EngineStage {
  id: string;
  label: string;
  threshold: number;
}

const STAGES: EngineStage[] = [
  { id: 'dep', label: 'Dependency Graph & AST Parsing', threshold: 25 },
  { id: 'sec', label: 'Security Rules & Taint Flow', threshold: 50 },
  { id: 'arch', label: 'Architecture & Layer Coupling', threshold: 75 },
  { id: 'health', label: 'Health Rating & Deductions', threshold: 95 },
];

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Running static security & architecture analysis...',
  targetPath,
  progressPercent = 0,
  stage,
  onCancel,
}) => {
  const percent = Math.max(0, Math.min(100, Math.round(progressPercent)));

  return (
    <div className="relative overflow-hidden panel-elevated p-8 shadow-2xl max-w-2xl mx-auto w-full animate-fade-in-up border-emerald-500/25">
      {/* Subtle Horizontal Moving Scan-Line Effect (disappears when analysis finishes) */}
      <div className="scanline-bar animate-scanline" />

      <div className="relative z-10 space-y-6">
        {/* Header HUD */}
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <ShieldCheck className="w-5 h-5 stroke-[2.2]" />
              </div>
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/30">
                  ANALYSIS ENGINE
                </span>
                {stage && (
                  <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
                    [{stage}]
                  </span>
                )}
              </div>
              <h3 className="text-sm font-bold text-white mt-0.5 tracking-tight">
                {message}
              </h3>
            </div>
          </div>

          <div className="text-right font-mono">
            <span className="text-2xl font-black text-emerald-400 tracking-tight">
              {percent}%
            </span>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider">Telemetry</p>
          </div>
        </div>

        {/* Target Repository Path */}
        {targetPath && (
          <div className="bg-[#080C14]/80 px-3.5 py-2 rounded-lg border border-slate-800/70 font-mono text-xs text-slate-300 flex items-center space-x-2">
            <span className="text-slate-500 select-none">Target:</span>
            <span className="text-slate-200 truncate">{targetPath}</span>
          </div>
        )}

        {/* Technical Progress Bar */}
        <div className="space-y-1.5">
          <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800/80 p-0.5">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400 rounded-full transition-all duration-300 ease-out shadow-[0_0_10px_rgba(16,185,129,0.5)]"
              style={{ width: `${Math.max(4, percent)}%` }}
            />
          </div>
        </div>

        {/* Live Technical Engine Checklist */}
        <div className="bg-[#080C14]/60 rounded-xl p-4 border border-slate-800/80 space-y-2.5 font-mono text-xs">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-800/60 pb-1.5 flex justify-between">
            <span>Pipeline Execution Sequence</span>
            <span>Status</span>
          </div>

          {STAGES.map((s, idx) => {
            const isDone = percent >= s.threshold;
            const prevThreshold = idx === 0 ? 0 : STAGES[idx - 1].threshold;
            const isActive = !isDone && (percent >= prevThreshold || (idx === 0 && percent === 0));

            return (
              <div
                key={s.id}
                className={`flex items-center justify-between py-1 px-1.5 rounded transition-colors ${
                  isActive ? 'bg-slate-800/40 text-white font-medium' : isDone ? 'text-slate-300' : 'text-slate-500'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  {isDone ? (
                    <span className="flex items-center justify-center w-4 h-4 rounded-full bg-emerald-950 border border-emerald-500/40 text-emerald-400">
                      <Check className="w-2.5 h-2.5 stroke-[3]" />
                    </span>
                  ) : isActive ? (
                    <span className="flex items-center justify-center w-4 h-4 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-400">
                      <Loader2 className="w-2.5 h-2.5 animate-spin" />
                    </span>
                  ) : (
                    <span className="flex items-center justify-center w-4 h-4 rounded-full bg-slate-900 border border-slate-800 text-slate-600">
                      <Circle className="w-2 h-2" />
                    </span>
                  )}
                  <span>{s.label}</span>
                </div>

                <div>
                  {isDone ? (
                    <span className="text-emerald-400 font-semibold text-[11px]">✓ COMPLETE</span>
                  ) : isActive ? (
                    <span className="text-cyan-400 font-semibold text-[11px] animate-pulse">◉ RUNNING</span>
                  ) : (
                    <span className="text-slate-600 text-[11px]">○ PENDING</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Footer Actions */}
        {onCancel && (
          <div className="flex justify-end pt-1">
            <button
              onClick={onCancel}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold text-rose-300 hover:text-white bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 rounded-lg transition-all cursor-pointer"
            >
              <XCircle className="w-3.5 h-3.5" />
              <span>Cancel Operation</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

