import React from 'react';
import { AlertCircle, ArrowDownRight } from 'lucide-react';
import { DeductionDTO } from '../../types';

interface DeductionsTableProps {
  deductions: DeductionDTO[];
  onSelectRule?: (ruleId: string) => void;
}

export const DeductionsTable: React.FC<DeductionsTableProps> = ({ deductions, onSelectRule }) => {
  if (!deductions || deductions.length === 0) {
    return (
      <div className="bg-[#121824]/60 border border-slate-800 rounded-xl p-6 text-center">
        <p className="text-xs font-semibold text-emerald-400">Zero Score Deductions Assessed</p>
        <p className="text-[11px] text-slate-500 mt-1">
          Codebase satisfies all baseline architecture and security static thresholds.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-[#121824]/80 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      <div className="px-5 py-3.5 border-b border-slate-800 bg-[#0E1420] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 text-amber-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Itemized Audit Log: Score Penalties ({deductions.length})
          </h3>
        </div>
        <span className="text-[11px] text-slate-500">
          Base 100 - Total Deductions = Final Score
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-[#0B0F17]/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-4 font-semibold">Rule ID</th>
              <th className="py-2.5 px-4 font-semibold">Category</th>
              <th className="py-2.5 px-4 font-semibold text-right">Points Deducted</th>
              <th className="py-2.5 px-4 font-semibold">Reason</th>
              <th className="py-2.5 px-4 font-semibold text-center">Items</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {deductions.map((d, index) => (
              <tr key={`${d.rule_id}-${index}`} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-2.5 px-4 font-bold text-emerald-400">
                  {onSelectRule ? (
                    <button
                      onClick={() => onSelectRule(d.rule_id)}
                      className="hover:underline hover:text-emerald-300 text-left"
                    >
                      {d.rule_id}
                    </button>
                  ) : (
                    d.rule_id
                  )}
                </td>
                <td className="py-2.5 px-4">
                  <span
                    className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      d.category === 'SECURITY'
                        ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60'
                        : 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/60'
                    }`}
                  >
                    {d.category}
                  </span>
                </td>
                <td className="py-2.5 px-4 text-right font-bold text-rose-400">
                  <span className="inline-flex items-center space-x-0.5">
                    <ArrowDownRight className="w-3 h-3 text-rose-500" />
                    <span>-{d.points_deducted.toFixed(1)}</span>
                  </span>
                </td>
                <td className="py-2.5 px-4 font-sans text-xs text-slate-300">{d.reason}</td>
                <td className="py-2.5 px-4 text-center font-bold text-slate-400">{d.item_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
