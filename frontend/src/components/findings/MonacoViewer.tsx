import React from 'react';
import Editor from '@monaco-editor/react';
import { FileCode, AlertTriangle, ShieldCheck, Copy, Check } from 'lucide-react';
import { FindingDTO } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { TaintTraceViewer } from './TaintTraceViewer';

interface MonacoViewerProps {
  finding: FindingDTO;
}

export const MonacoViewer: React.FC<MonacoViewerProps> = ({ finding }) => {
  const [copied, setCopied] = React.useState(false);

  const copyCode = () => {
    navigator.clipboard.writeText(finding.evidence.snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const startLine = finding.location.line_start || 1;

  return (
    <div className="bg-[#101622] border border-slate-800 rounded-xl overflow-hidden flex flex-col h-full shadow-2xl">
      {/* File & Finding Header */}
      <div className="p-4 border-b border-slate-800 bg-[#0B0F17] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5 min-w-0">
          <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="font-mono text-xs font-bold text-slate-200 truncate">
            {finding.location.file_path}
          </span>
          <span className="text-xs font-mono text-slate-500 shrink-0">
            :{finding.location.line_start}
            {finding.location.line_end && finding.location.line_end !== finding.location.line_start
              ? `-${finding.location.line_end}`
              : ''}
          </span>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <SeverityBadge severity={finding.severity} />
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            {finding.rule_id}
          </span>
          <button
            onClick={copyCode}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title="Copy snippet"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Finding Title & Explanation */}
      <div className="p-4 bg-[#121824]/60 border-b border-slate-800 space-y-2 text-xs">
        <div className="flex items-start space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-slate-100">{finding.message || finding.rule_name}</p>
            <p className="text-slate-400 mt-1 leading-relaxed">{finding.description}</p>
          </div>
        </div>
      </div>

      {/* Intraprocedural Taint Flow Trace (Phase 13) */}
      {finding.dataflow_evidence && (
        <div className="px-4 py-1 bg-[#0b0f17] border-b border-slate-800 max-h-60 overflow-y-auto">
          <TaintTraceViewer trace={finding.dataflow_evidence} />
        </div>
      )}

      {/* Monaco Code Viewer */}
      <div className="flex-1 min-h-[220px] relative bg-[#1E1E1E]">
        <Editor
          height="100%"
          language={finding.evidence.language || 'plaintext'}
          value={finding.evidence.snippet}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: false },
            fontSize: 12,
            fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
            lineNumbers: (lineNumber: number) => String(lineNumber + startLine - 1),
            lineNumbersMinChars: 4,
            scrollBeyondLastLine: false,
            renderLineHighlight: 'all',
            automaticLayout: true,
            domReadOnly: true,
            padding: { top: 8, bottom: 8 },
            wordWrap: 'on',
          }}
        />
      </div>

      {/* Remediation Footer */}
      <div className="p-3.5 bg-[#0B0F17] border-t border-slate-800 text-xs flex items-start space-x-2.5">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-emerald-300">Prescribed Remediation:</span>
          <p className="text-slate-400 leading-relaxed">{finding.remediation}</p>
        </div>
      </div>
    </div>
  );
};
