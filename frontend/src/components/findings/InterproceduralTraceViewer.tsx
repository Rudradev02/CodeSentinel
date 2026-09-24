import React from 'react';
import { ArrowRight, Shield, AlertTriangle, Radio, GitFork, FileCode, Layers } from 'lucide-react';
import type { InterproceduralTaintTraceDTO } from '../../types/api';

interface InterproceduralTraceViewerProps {
  trace: InterproceduralTaintTraceDTO;
  onSelectLine?: (line: number, filePath?: string) => void;
}

export const InterproceduralTraceViewer: React.FC<InterproceduralTraceViewerProps> = ({
  trace,
  onSelectLine,
}) => {
  return (
    <div className="bg-slate-900 border border-indigo-900/60 rounded-lg p-4 my-3 text-sm shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <GitFork className="w-4 h-4 text-indigo-400 animate-pulse" />
          <span className="font-semibold text-slate-100">
            Interprocedural Taint Flow Trace
          </span>
          <span className="text-xs px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/60 font-mono">
            {trace.flow_type}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
          {trace.alias_evidence && trace.alias_evidence.length > 0 && (
            <span className="flex items-center gap-1 bg-emerald-950/80 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800/60">
              Alias-Resolved
            </span>
          )}
          {trace.field_evidence && trace.field_evidence.length > 0 && (
            <span className="flex items-center gap-1 bg-teal-950/80 text-teal-300 px-2 py-0.5 rounded border border-teal-800/60">
              Field-Sensitive
            </span>
          )}
          <span className="flex items-center gap-1 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/50">
            <Layers className="w-3 h-3 text-indigo-400" />
            Depth: {trace.total_depth} hop{trace.total_depth === 1 ? '' : 's'}
          </span>
          <span className="flex items-center gap-1 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/50">
            <FileCode className="w-3 h-3 text-amber-400" />
            {trace.files_involved.length} file{trace.files_involved.length === 1 ? '' : 's'}
          </span>
        </div>
      </div>

      {/* Path summary banner */}
      <div className="bg-slate-950/90 border border-indigo-950 rounded p-2.5 mb-3 font-mono text-xs text-slate-300 flex items-center gap-2 overflow-x-auto">
        <span className="text-indigo-400 font-sans uppercase font-bold tracking-wider text-[10px] shrink-0">
          Call Flow:
        </span>
        <span className="text-slate-200">{trace.path_summary}</span>
      </div>

      {/* Files Involved pill list */}
      <div className="flex items-center gap-1.5 mb-3 flex-wrap text-xs">
        <span className="text-slate-500 font-medium mr-1 text-[11px]">Files:</span>
        {trace.files_involved.map((file) => (
          <span
            key={file}
            className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800/70 text-slate-300 border border-slate-700/60"
          >
            {file}
          </span>
        ))}
      </div>

      {/* Timeline Steps */}
      <div className="space-y-2">
        {/* 1. Source Step */}
        <div
          onClick={() => onSelectLine?.(trace.source.line, trace.source.file_path)}
          className="flex items-start gap-3 p-2.5 rounded bg-rose-950/30 border border-rose-900/40 hover:bg-rose-900/40 cursor-pointer transition-colors group"
        >
          <div className="w-5 h-5 rounded-full bg-rose-600/20 text-rose-400 flex items-center justify-center shrink-0 mt-0.5 border border-rose-500/40">
            <Radio className="w-3 h-3" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <span className="font-bold text-rose-400 uppercase tracking-wider">
                Source
              </span>
              <span className="text-slate-400 font-mono">
                {trace.source.file_path}:{trace.source.line}:{trace.source.column}
              </span>
              {trace.source.symbol_name && (
                <span className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.2 rounded text-[11px]">
                  {trace.source.symbol_name}
                </span>
              )}
            </div>
            <div className="mt-1 font-mono text-xs text-rose-200 bg-slate-950 px-2 py-1 rounded border border-rose-900/30 break-all">
              {trace.source.expression}
            </div>
          </div>
        </div>

        {/* 2. Cross-Function Call Chain Steps */}
        {trace.call_chain.map((step, idx) => (
          <div
            key={`${step.caller_function}-${step.callee_function}-${idx}`}
            onClick={() => onSelectLine?.(step.call_site_line, step.caller_file)}
            className="flex items-start gap-3 p-2.5 rounded bg-indigo-950/20 border border-indigo-900/40 hover:bg-indigo-900/30 cursor-pointer transition-colors ml-4 pl-3 border-l-2 border-l-indigo-500/70"
          >
            <div className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center shrink-0 mt-0.5 border border-indigo-500/40">
              <ArrowRight className="w-3 h-3" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs flex-wrap">
                <span className="font-bold text-indigo-300 uppercase tracking-wider">
                  Hop {idx + 1}: Cross-Function Call
                </span>
                <span className="text-slate-400 font-mono text-[11px]">
                  {step.caller_file}:{step.call_site_line}
                </span>
                <span className="text-xs px-1.5 py-0.2 rounded bg-indigo-900/60 text-indigo-200 border border-indigo-700/50 font-mono text-[10px]">
                  {step.taint_action}
                </span>
                {step.receiver_type && (
                  <span className="text-xs px-1.5 py-0.2 rounded bg-purple-900/60 text-purple-200 border border-purple-700/50 font-mono text-[10px] flex items-center gap-1">
                    <span>Receiver:</span>
                    <strong className="text-purple-100">{step.receiver_type}</strong>
                    {step.receiver_confidence && (
                      <span className="opacity-80">({step.receiver_confidence})</span>
                    )}
                  </span>
                )}
                {step.alias_path && (
                  <span className="text-xs px-1.5 py-0.2 rounded bg-emerald-900/60 text-emerald-200 border border-emerald-700/50 font-mono text-[10px] flex items-center gap-1">
                    <span>Alias:</span>
                    <strong className="text-emerald-100">{step.alias_path}</strong>
                  </span>
                )}
                {step.field_path && (
                  <span className="text-xs px-1.5 py-0.2 rounded bg-teal-900/60 text-teal-200 border border-teal-700/50 font-mono text-[10px] flex items-center gap-1">
                    <span>Field:</span>
                    <strong className="text-teal-100">{step.field_path}</strong>
                  </span>
                )}
                {step.allocation_site && (
                  <span
                    className="text-xs px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700/50 font-mono text-[10px] flex items-center gap-1"
                    title={step.allocation_site}
                  >
                    <span>Alloc:</span>
                    <span className="text-slate-200">{step.allocation_site.split(':').slice(-2).join(':')}</span>
                  </span>
                )}
                {step.context_id && step.context_id !== "ROOT" && (
                  <span className="text-xs px-1.5 py-0.2 rounded bg-cyan-900/60 text-cyan-200 border border-cyan-700/50 font-mono text-[10px]">
                    Context: {step.context_id}
                  </span>
                )}
              </div>

              <div className="mt-1.5 font-mono text-xs text-slate-200 bg-slate-950 p-2 rounded border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-indigo-200">
                  <span className="text-slate-500">caller:</span>
                  <span className="font-semibold text-slate-100">{step.caller_function}()</span>
                  <span className="text-slate-500">&rarr;</span>
                  <span className="text-slate-500">callee:</span>
                  <span className="font-semibold text-indigo-300">{step.callee_function}()</span>
                </div>
                <div className="text-[11px] text-slate-400 flex items-center gap-2">
                  <span>Parameter: <code className="text-amber-300">param[{step.argument_index}] '{step.callee_param_name}'</code></span>
                  <span>in <code className="text-slate-300">{step.callee_file}</code></span>
                </div>
              </div>
            </div>
          </div>
        ))}

        {/* 3. Sanitizer Step (if present) */}
        {trace.sanitizer && (
          <div className="flex items-start gap-3 p-2.5 rounded bg-emerald-950/30 border border-emerald-900/40 ml-4 pl-3 border-l-2 border-l-emerald-500/60">
            <div className="w-5 h-5 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0 mt-0.5 border border-emerald-500/30">
              <Shield className="w-3 h-3" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-bold text-emerald-400 uppercase tracking-wider">
                  Sanitizer
                </span>
                <span className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.2 rounded text-[11px]">
                  {trace.sanitizer.sanitizer_id}
                </span>
              </div>
              <div className="mt-1 font-mono text-xs text-emerald-200 bg-slate-950 px-2 py-1 rounded border border-emerald-900/30 break-all">
                Pattern: {trace.sanitizer.callee_pattern} (Strength: {trace.sanitizer.strength})
              </div>
            </div>
          </div>
        )}

        {/* 4. Sink Step */}
        <div
          onClick={() => onSelectLine?.(trace.sink.line, trace.sink.file_path)}
          className="flex items-start gap-3 p-2.5 rounded bg-amber-950/30 border border-amber-900/40 hover:bg-amber-900/40 cursor-pointer transition-colors ml-4 pl-3 border-l-2 border-l-amber-500/80 group"
        >
          <div className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0 mt-0.5 border border-amber-500/40">
            <AlertTriangle className="w-3 h-3" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <span className="font-bold text-amber-400 uppercase tracking-wider">
                Dangerous Sink Invocation
              </span>
              <span className="text-slate-400 font-mono">
                {trace.sink.file_path}:{trace.sink.line}:{trace.sink.column}
              </span>
              <span className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.2 rounded text-[11px]">
                {trace.sink.sink_id}
              </span>
            </div>
            <div className="mt-1 font-mono text-xs text-amber-200 bg-slate-950 px-2 py-1 rounded border border-amber-900/30 break-all">
              Callee: {trace.sink.callee} (Arg #{trace.sink.argument_index}: {trace.sink.tainted_argument || 'tainted payload'})
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
