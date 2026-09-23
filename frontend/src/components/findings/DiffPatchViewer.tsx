import React, { useState } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { Check, Copy, FileDiff, ShieldAlert } from 'lucide-react';
import { ProposedPatchDTO } from '../../types';

interface DiffPatchViewerProps {
  patch: ProposedPatchDTO;
  language?: string;
}

export const DiffPatchViewer: React.FC<DiffPatchViewerProps> = ({ patch, language = 'plaintext' }) => {
  const [copied, setCopied] = useState(false);

  const copyDiff = () => {
    navigator.clipboard.writeText(patch.unified_diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0B0F17] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-xl">
      {/* Header */}
      <div className="p-3 bg-[#121824] border-b border-slate-800 flex items-center justify-between gap-3">
        <div className="flex items-center space-x-2 min-w-0">
          <FileDiff className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="font-mono text-xs font-semibold text-slate-200 truncate">
            {patch.file_path}
          </span>
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            Proposed Remediation
          </span>
        </div>

        <button
          onClick={copyDiff}
          className="flex items-center space-x-1 px-2.5 py-1 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700"
          title="Copy unified diff to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400">Copied Diff</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-slate-400" />
              <span>Copy Diff</span>
            </>
          )}
        </button>
      </div>

      {/* Advisory Warning Banner */}
      <div className="px-3.5 py-2 bg-amber-500/10 border-b border-amber-500/20 flex items-center space-x-2 text-[11px] text-amber-300">
        <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span>
          AI-generated proposed remediation. Review syntax, logic, and test coverage carefully before applying.
        </span>
      </div>

      {/* Patch Explanation */}
      {patch.explanation && (
        <div className="p-3 bg-[#101622] border-b border-slate-800 text-xs text-slate-300">
          <span className="font-semibold text-slate-400 text-[11px] uppercase tracking-wider block mb-1">
            Patch Strategy:
          </span>
          <p className="leading-relaxed">{patch.explanation}</p>
        </div>
      )}

      {/* Side-by-Side Monaco Diff Editor */}
      <div className="h-[280px] bg-[#1E1E1E] relative">
        <DiffEditor
          height="100%"
          language={language}
          original={patch.original_snippet}
          modified={patch.patched_snippet}
          theme="vs-dark"
          options={{
            readOnly: true,
            renderSideBySide: true,
            minimap: { enabled: false },
            fontSize: 12,
            fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
            lineNumbersMinChars: 3,
            scrollBeyondLastLine: false,
            automaticLayout: true,
            padding: { top: 8, bottom: 8 },
            wordWrap: 'on',
          }}
        />
      </div>
    </div>
  );
};
