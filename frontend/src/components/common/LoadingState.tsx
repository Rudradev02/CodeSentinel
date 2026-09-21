import React from 'react';
import { ShieldCheck } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  targetPath?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Running static security & architecture analysis...',
  targetPath,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-16 space-y-6 bg-[#121824]/60 border border-slate-800 rounded-2xl">
      <div className="relative">
        <div className="w-16 h-16 rounded-full border-4 border-emerald-500/20 border-t-emerald-400 animate-spin" />
        <div className="absolute inset-0 flex items-center justify-center text-emerald-400">
          <ShieldCheck className="w-7 h-7" />
        </div>
      </div>
      <div className="text-center space-y-2">
        <h3 className="text-lg font-semibold text-slate-100">{message}</h3>
        {targetPath && (
          <p className="text-sm font-mono text-slate-400 max-w-lg truncate">
            Target: {targetPath}
          </p>
        )}
        <p className="text-xs text-slate-500">
          Parsing ASTs • Resolving Dependencies • Computing Component Graph • Evaluating Rules
        </p>
      </div>
    </div>
  );
};
