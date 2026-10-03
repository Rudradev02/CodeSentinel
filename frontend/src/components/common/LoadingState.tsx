import React, { useEffect, useState } from 'react';
import { ShieldCheck, XCircle, Check, Loader2, Circle } from 'lucide-react';

interface LoadingStateProps {
  message?: string | null;
  targetPath?: string;
  progressPercent?: number;
  stage?: string | null;
  isCompleted?: boolean;
  onCancel?: () => void;
}

interface EngineStage {
  id: string;
  label: string;
  sublabel: string;
  threshold: number;
}

const STAGES: EngineStage[] = [
  {
    id: 'ast',
    label: 'File Discovery & AST Syntax Parsing',
    sublabel: 'Language detection, tree-sitter & AST scope extraction',
    threshold: 25,
  },
  {
    id: 'dep',
    label: 'Dependency Graph & Call Sites',
    sublabel: 'Module resolution, cycle detection & static call graph',
    threshold: 50,
  },
  {
    id: 'sec',
    label: 'Security Rules & Taint Flow',
    sublabel: 'CWE/OWASP detectors, sanitization & data-flow verification',
    threshold: 75,
  },
  {
    id: 'health',
    label: 'Architecture Coupling & Health Score',
    sublabel: 'Instability metrics, layer coupling & Martin deductions',
    threshold: 95,
  },
];

export const LoadingState: React.FC<LoadingStateProps> = ({
  message: initialMessage,
  targetPath,
  progressPercent = 0,
  stage: initialStage,
  isCompleted = false,
  onCancel,
}) => {
  const [simulatedPercent, setSimulatedPercent] = useState<number>(() =>
    progressPercent > 0 ? progressPercent : 6
  );

  useEffect(() => {
    if (isCompleted || progressPercent >= 100) {
      setSimulatedPercent(100);
      return;
    }

    // If authoritative server progress is active, sync directly
    if (progressPercent > 0) {
      setSimulatedPercent(progressPercent);
      return;
    }

    // Otherwise, simulate a realistic progression through the pipeline
    const interval = setInterval(() => {
      setSimulatedPercent((prev) => {
        if (prev >= 94) {
          // Gently hold at 94% until completion response arrives
          return Math.min(95, prev + 0.1);
        }
        if (prev < 25) {
          return Math.min(25, prev + Math.floor(Math.random() * 3 + 2));
        }
        if (prev < 50) {
          return Math.min(50, prev + Math.floor(Math.random() * 3 + 2));
        }
        if (prev < 75) {
          return Math.min(75, prev + Math.floor(Math.random() * 2 + 1.5));
        }
        return Math.min(94, prev + 1);
      });
    }, 140);

    return () => clearInterval(interval);
  }, [progressPercent, isCompleted]);

  const percent = isCompleted
    ? 100
    : Math.max(0, Math.min(100, Math.round(progressPercent > 0 ? progressPercent : simulatedPercent)));

  // Derive dynamic stage and message if not provided by server
  let activeStage = initialStage;
  let activeMessage = initialMessage;

  if (percent >= 100) {
    activeStage = 'COMPLETED';
    activeMessage = 'Analysis complete! Loading dashboard telemetry...';
  } else if (!initialStage || initialStage === 'QUEUED' || initialStage === 'INITIALIZING') {
    if (percent < 25) {
      activeStage = 'AST_PARSING';
      activeMessage = 'Discovering source files & parsing syntax trees...';
    } else if (percent < 50) {
      activeStage = 'DEPENDENCY_GRAPH';
      activeMessage = 'Resolving module dependencies & building call graph...';
    } else if (percent < 75) {
      activeStage = 'SECURITY_RULES';
      activeMessage = 'Evaluating static security rules & taint flow paths...';
    } else if (percent < 95) {
      activeStage = 'HEALTH_RATING';
      activeMessage = 'Analyzing layer coupling & computing codebase health...';
    } else {
      activeStage = 'SYNTHESIZING';
      activeMessage = 'Synthesizing report & finalizing diagnostics...';
    }
  }

  return (
    <div className="relative overflow-hidden panel-elevated p-8 shadow-2xl max-w-2xl mx-auto w-full animate-fade-in-up border-emerald-500/25">
      {/* Subtle Horizontal Moving Scan-Line Effect */}
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
                {activeStage && (
                  <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider font-semibold">
                    [{activeStage}]
                  </span>
                )}
              </div>
              <h3 className="text-sm font-bold text-white mt-0.5 tracking-tight transition-all">
                {activeMessage}
              </h3>
            </div>
          </div>

          <div className="text-right font-mono">
            <span className={`text-2xl font-black tracking-tight transition-colors ${percent >= 100 ? 'text-emerald-400' : 'text-cyan-400'}`}>
              {percent}%
            </span>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider">
              {percent >= 100 ? 'Complete' : 'Telemetry'}
            </p>
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
          <div className="flex justify-between text-[11px] font-mono text-slate-400">
            <span className="text-cyan-400 flex items-center space-x-1.5">
              <span className={`inline-block w-1.5 h-1.5 rounded-full ${percent >= 100 ? 'bg-emerald-400' : 'bg-cyan-400 animate-pulse'}`} />
              <span>{activeStage || 'PROCESSING'}</span>
            </span>
            <span className="text-slate-300 font-semibold">{percent}%</span>
          </div>
          <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800/80 p-0.5">
            <div
              className={`h-full rounded-full transition-all duration-300 ease-out shadow-[0_0_10px_rgba(16,185,129,0.5)] ${
                percent >= 100
                  ? 'bg-gradient-to-r from-emerald-500 to-emerald-400'
                  : 'bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400'
              }`}
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
            const isDone = percent >= s.threshold || percent === 100;
            const prevThreshold = idx === 0 ? 0 : STAGES[idx - 1].threshold;
            const isActive = !isDone && percent >= prevThreshold;

            return (
              <div
                key={s.id}
                className={`flex items-center justify-between py-2 px-2.5 rounded-lg transition-all duration-200 ${
                  isActive
                    ? 'bg-slate-800/60 border border-slate-700/60 text-white shadow-sm'
                    : isDone
                    ? 'text-slate-300'
                    : 'text-slate-500'
                }`}
              >
                <div className="flex items-center space-x-3 min-w-0">
                  {isDone ? (
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-950/80 border border-emerald-500/60 text-emerald-400 shrink-0">
                      <Check className="w-3 h-3 stroke-[3]" />
                    </span>
                  ) : isActive ? (
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-cyan-950/80 border border-cyan-500/60 text-cyan-400 shrink-0">
                      <Loader2 className="w-3 h-3 animate-spin" />
                    </span>
                  ) : (
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-slate-900/80 border border-slate-800 text-slate-600 shrink-0">
                      <Circle className="w-2 h-2" />
                    </span>
                  )}
                  <div className="min-w-0">
                    <p className={`text-xs font-semibold truncate ${isActive ? 'text-white' : isDone ? 'text-slate-200' : 'text-slate-400'}`}>
                      {s.label}
                    </p>
                    <p className="text-[10px] text-slate-500 font-sans truncate">
                      {s.sublabel}
                    </p>
                  </div>
                </div>

                <div className="shrink-0 ml-3">
                  {isDone ? (
                    <span className="inline-flex items-center space-x-1 text-emerald-400 font-semibold text-[11px] bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                      <span>✓ COMPLETE</span>
                    </span>
                  ) : isActive ? (
                    <span className="inline-flex items-center space-x-1 text-cyan-300 font-semibold text-[11px] bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30 animate-pulse">
                      <span>◉ RUNNING</span>
                    </span>
                  ) : (
                    <span className="text-slate-600 text-[11px] font-mono px-2 py-0.5">
                      PENDING
                    </span>
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


