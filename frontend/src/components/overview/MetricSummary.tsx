import React from 'react';
import { Files, Code2, Network, Clock } from 'lucide-react';
import { AnalysisSummaryDTO } from '../../types';

interface MetricSummaryProps {
  summary: AnalysisSummaryDTO;
}

export const MetricSummary: React.FC<MetricSummaryProps> = ({ summary }) => {
  return (
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
  );
};
