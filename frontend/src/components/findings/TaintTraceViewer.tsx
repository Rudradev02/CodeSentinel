import React from 'react';
import { ArrowRight, Shield, AlertTriangle, Radio, Code2 } from 'lucide-react';
import type { TaintTraceDTO } from '../../types/api';

interface TaintTraceViewerProps {
  trace: TaintTraceDTO;
  onSelectLine?: (line: number) => void;
}

export const TaintTraceViewer: React.FC<TaintTraceViewerProps> = ({
  trace,
  onSelectLine,
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 my-3 text-sm">
      <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
          <span className="font-semibold text-slate-200">
            Intraprocedural Taint Flow Trace
          </span>
          <span className="text-xs px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/60 font-mono">
            {trace.flow_type}
          </span>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          {trace.propagation.length + 2} trace steps
        </span>
      </div>

      {/* Path summary banner */}
      <div className="bg-slate-950/80 border border-slate-800 rounded p-2.5 mb-3 font-mono text-xs text-slate-300 flex items-center gap-2 overflow-x-auto">
        <span className="text-slate-500 font-sans uppercase font-bold tracking-wider text-[10px]">
          Flow:
        </span>
        <span className="text-slate-200">{trace.path_summary}</span>
      </div>

      {/* Timeline Steps */}
      <div className="space-y-2">
        {/* 1. Source Step */}
        <div
          onClick={() => onSelectLine?.(trace.source.line)}
          className="flex items-start gap-3 p-2 rounded bg-rose-950/30 border border-rose-900/40 hover:bg-rose-900/30 cursor-pointer transition-colors group"
        >
          <div className="w-5 h-5 rounded-full bg-rose-600/20 text-rose-400 flex items-center justify-center shrink-0 mt-0.5 border border-rose-500/40">
            <Radio className="w-3 h-3" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-xs">
              <span className="font-bold text-rose-400 uppercase tracking-wider">
                Source
              </span>
              <span className="text-slate-400">
                Line {trace.source.line}:{trace.source.column}
              </span>
              {trace.source.symbol_name && (
                <span className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.2 rounded">
                  {trace.source.symbol_name}
                </span>
              )}
            </div>
            <div className="mt-1 font-mono text-xs text-rose-200 bg-slate-950 px-2 py-1 rounded border border-rose-900/30 break-all">
              {trace.source.expression}
            </div>
          </div>
        </div>

        {/* 2. Propagation Steps */}
        {trace.propagation.map((step) => (
          <div
            key={step.step}
            onClick={() => onSelectLine?.(step.line)}
            className="flex items-start gap-3 p-2 rounded bg-slate-950/40 border border-slate-800/80 hover:bg-slate-800/50 cursor-pointer transition-colors ml-4 pl-3 border-l-2 border-l-amber-500/60"
          >
            <div className="w-5 h-5 rounded-full bg-amber-500/10 text-amber-400 flex items-center justify-center shrink-0 mt-0.5 border border-amber-500/30">
              <ArrowRight className="w-3 h-3" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-bold text-amber-400 uppercase tracking-wider">
                  Step {step.step}: {step.operation}
                </span>
                <span className="text-slate-400">Line {step.line}</span>
                {step.to_symbol && (
                  <span className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.2 rounded">
                    &rarr; {step.to_symbol}
                  </span>
                )}
              </div>
              <div className="mt-1 font-mono text-xs text-slate-300 bg-slate-950 px-2 py-1 rounded border border-slate-800/60 break-all">
                {step.expression}
              </div>
            </div>
          </div>
        ))}

        {/* 3. Sanitizer Step (if present) */}
        {trace.sanitizer && (
          <div className="flex items-start gap-3 p-2 rounded bg-emerald-950/30 border border-emerald-900/40 ml-4 pl-3 border-l-2 border-l-emerald-500/60">
            <div className="w-5 h-5 rounded-full bg-emerald-600/20 text-emerald-400 flex items-center justify-center shrink-0 mt-0.5 border border-emerald-500/40">
              <Shield className="w-3 h-3" />
            </div>
            <div className="min-w-0 flex-1 text-xs">
              <div className="font-bold text-emerald-400 uppercase tracking-wider">
                Sanitizer Applied
              </div>
              <div className="text-emerald-300 mt-1 font-mono">
                {trace.sanitizer.callee_pattern} ({trace.sanitizer.strength})
              </div>
            </div>
          </div>
        )}

        {/* 4. Sink Step */}
        <div
          onClick={() => onSelectLine?.(trace.sink.line)}
          className="flex items-start gap-3 p-2 rounded bg-red-950/40 border border-red-900/60 hover:bg-red-900/30 cursor-pointer transition-colors group"
        >
          <div className="w-5 h-5 rounded-full bg-red-600/20 text-red-400 flex items-center justify-center shrink-0 mt-0.5 border border-red-500/40">
            <AlertTriangle className="w-3 h-3" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-xs">
              <span className="font-bold text-red-400 uppercase tracking-wider">
                Sensitive Sink
              </span>
              <span className="text-slate-400">
                Line {trace.sink.line}:{trace.sink.column}
              </span>
              <span className="font-mono text-red-300 bg-red-950/80 px-1.5 py-0.2 rounded border border-red-800/40">
                {trace.sink.callee}
              </span>
            </div>
            {trace.sink.tainted_argument && (
              <div className="mt-1 text-xs text-slate-300 flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-slate-400" />
                <span>Tainted Argument (Index {trace.sink.argument_index}):</span>
                <span className="font-mono text-rose-300 font-semibold">
                  {trace.sink.tainted_argument}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
