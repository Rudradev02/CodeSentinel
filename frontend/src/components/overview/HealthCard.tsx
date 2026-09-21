import React from 'react';
import { ShieldAlert, Cpu, HeartPulse } from 'lucide-react';
import { HealthScoreDTO } from '../../types';

interface HealthCardProps {
  health: HealthScoreDTO;
}

function getGradeColor(grade: string): { bg: string; text: string; border: string } {
  switch (grade.toUpperCase()) {
    case 'A':
      return { bg: 'bg-emerald-950/80', text: 'text-emerald-400', border: 'border-emerald-700/80' };
    case 'B':
      return { bg: 'bg-blue-950/80', text: 'text-blue-400', border: 'border-blue-700/80' };
    case 'C':
      return { bg: 'bg-amber-950/80', text: 'text-amber-400', border: 'border-amber-700/80' };
    case 'D':
      return { bg: 'bg-orange-950/80', text: 'text-orange-400', border: 'border-orange-700/80' };
    default:
      return { bg: 'bg-rose-950/80', text: 'text-rose-400', border: 'border-rose-700/80' };
  }
}

export const HealthCard: React.FC<HealthCardProps> = ({ health }) => {
  const overallColors = getGradeColor(health.overall_grade);
  const archColors = getGradeColor(health.architecture_health.grade);
  const secColors = getGradeColor(health.security_posture.grade);

  return (
    <div className="bg-[#121824]/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <HeartPulse className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center space-x-2">
              <span>Deterministic Codebase Health Rating</span>
              <span className="text-xs font-normal text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                Phase 7 Authoritative
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              100-point composite static quality & security posture (55% Security, 45% Architecture)
            </p>
          </div>
        </div>

        {/* Overall Grade Pill */}
        <div className="flex items-center space-x-3 bg-[#0B0F17] px-4 py-2 rounded-xl border border-slate-800">
          <div className="text-right">
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Composite Score</p>
            <p className="text-2xl font-black text-white tracking-tight leading-none">
              {health.overall_score.toFixed(1)}
              <span className="text-xs font-normal text-slate-500"> / 100</span>
            </p>
          </div>
          <div
            className={`w-12 h-12 rounded-xl flex items-center justify-center font-black text-2xl border ${overallColors.bg} ${overallColors.text} ${overallColors.border} shadow-lg`}
          >
            {health.overall_grade}
          </div>
        </div>
      </div>

      {/* Sub-Score Breakdown Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Security Posture */}
        <div className="bg-[#0E1420] border border-slate-800/80 rounded-xl p-4.5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <ShieldAlert className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-semibold text-slate-200">Security Posture</span>
              <span className="text-[10px] text-slate-400">(Weight: 55%)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold text-white">
                {health.security_posture.score.toFixed(1)}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-bold border ${secColors.bg} ${secColors.text} ${secColors.border}`}
              >
                Grade {health.security_posture.grade}
              </span>
            </div>
          </div>
          {/* Progress bar */}
          <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-500"
              style={{ width: `${Math.max(0, Math.min(100, health.security_posture.score))}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] text-slate-500">
            <span>Deductions: {health.security_posture.deductions.length}</span>
            <span>Scale: 0 - 100</span>
          </div>
        </div>

        {/* Architecture Health */}
        <div className="bg-[#0E1420] border border-slate-800/80 rounded-xl p-4.5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-slate-200">Architecture Health</span>
              <span className="text-[10px] text-slate-400">(Weight: 45%)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold text-white">
                {health.architecture_health.score.toFixed(1)}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-bold border ${archColors.bg} ${archColors.text} ${archColors.border}`}
              >
                Grade {health.architecture_health.grade}
              </span>
            </div>
          </div>
          {/* Progress bar */}
          <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-400 transition-all duration-500"
              style={{ width: `${Math.max(0, Math.min(100, health.architecture_health.score))}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] text-slate-500">
            <span>Deductions: {health.architecture_health.deductions.length}</span>
            <span>Scale: 0 - 100</span>
          </div>
        </div>
      </div>

      {/* Summary note if present */}
      {health.summary && (
        <div className="text-xs text-slate-400 italic bg-[#0B0F17]/60 px-4 py-2.5 rounded-lg border border-slate-800/50">
          "{health.summary}"
        </div>
      )}
    </div>
  );
};
