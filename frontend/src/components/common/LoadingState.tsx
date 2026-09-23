import React from 'react';
import { ShieldCheck, XCircle } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  targetPath?: string;
  progressPercent?: number;
  stage?: string | null;
  onCancel?: () => void;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Running static security & architecture analysis...',
  targetPath,
  progressPercent = 0,
  stage,
  onCancel,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 space-y-6 bg-[#121824]/80 border border-slate-800 rounded-2xl shadow-xl max-w-xl mx-auto w-full">
      <div className="relative">
        <div className="w-16 h-16 rounded-full border-4 border-emerald-500/20 border-t-emerald-400 animate-spin" />
        <div className="absolute inset-0 flex items-center justify-center text-emerald-400">
          <ShieldCheck className="w-7 h-7" />
        </div>
      </div>

      <div className="text-center space-y-2 w-full">
        <div className="flex items-center justify-center gap-2">
          <h3 className="text-lg font-semibold text-slate-100">{message}</h3>
          {stage && (
            <span className="px-2 py-0.5 text-xs font-mono font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 rounded-full uppercase tracking-wider">
              {stage}
            </span>
          )}
        </div>

        {targetPath && (
          <p className="text-sm font-mono text-slate-400 max-w-lg truncate mx-auto">
            Target: {targetPath}
          </p>
        )}

        {/* Real-time Progress Bar */}
        <div className="w-full pt-3 space-y-1.5">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400 px-1">
            <span>Progress</span>
            <span className="font-semibold text-emerald-400">{Math.round(progressPercent)}%</span>
          </div>
          <div className="w-full h-2.5 bg-slate-900/90 rounded-full overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 rounded-full transition-all duration-300 ease-out"
              style={{ width: `${Math.max(5, Math.min(100, progressPercent))}%` }}
            />
          </div>
        </div>

        <p className="text-xs text-slate-500 pt-2">
          Parsing ASTs • Resolving Dependencies • Building Architecture Graph • Security & Health Rules
        </p>
      </div>

      {onCancel && (
        <button
          onClick={onCancel}
          className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-rose-400 hover:text-rose-300 bg-rose-950/30 hover:bg-rose-950/50 border border-rose-800/40 rounded-lg transition-colors cursor-pointer"
        >
          <XCircle className="w-4 h-4" />
          Cancel Analysis
        </button>
      )}
    </div>
  );
};
