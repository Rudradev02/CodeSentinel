import React, { useEffect, useState } from 'react';
import { ShieldAlert, Cpu, HeartPulse, Check, Loader2, Circle, Radio } from 'lucide-react';
import { HealthScoreDTO } from '../../types';

interface HealthCardProps {
  health: HealthScoreDTO;
}

function getGradeStyles(grade: string) {
  switch (grade.toUpperCase()) {
    case 'A':
      return {
        badgeBg: 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40',
        strokeGradient: ['#10B981', '#06B6D4'],
        glow: 'rgba(16, 185, 129, 0.25)',
        text: 'text-emerald-400',
      };
    case 'B':
      return {
        badgeBg: 'bg-cyan-950/70 text-cyan-300 border-cyan-500/40',
        strokeGradient: ['#06B6D4', '#3B82F6'],
        glow: 'rgba(6, 182, 212, 0.25)',
        text: 'text-cyan-400',
      };
    case 'C':
      return {
        badgeBg: 'bg-amber-950/70 text-amber-300 border-amber-500/40',
        strokeGradient: ['#F59E0B', '#D97706'],
        glow: 'rgba(245, 158, 11, 0.25)',
        text: 'text-amber-400',
      };
    case 'D':
      return {
        badgeBg: 'bg-orange-950/70 text-orange-300 border-orange-500/40',
        strokeGradient: ['#F97316', '#EA580C'],
        glow: 'rgba(249, 115, 22, 0.25)',
        text: 'text-orange-400',
      };
    default:
      return {
        badgeBg: 'bg-rose-950/70 text-rose-300 border-rose-500/40',
        strokeGradient: ['#F43F5E', '#E11D48'],
        glow: 'rgba(244, 63, 94, 0.25)',
        text: 'text-rose-400',
      };
  }
}

// Lightweight animated number hook honoring prefers-reduced-motion
function useAnimatedNumber(target: number, durationMs = 600): number {
  const [displayVal, setDisplayVal] = useState(target);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplayVal(target);
      return;
    }

    let startTimestamp: number | null = null;
    let frameId: number;
    const startVal = displayVal;

    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / durationMs, 1);
      const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setDisplayVal(startVal + (target - startVal) * ease);

      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [target]);

  return displayVal;
}

export const HealthCard: React.FC<HealthCardProps> = ({ health }) => {
  const animatedScore = useAnimatedNumber(health.overall_score);
  const animatedSec = useAnimatedNumber(health.security_posture.score);
  const animatedArch = useAnimatedNumber(health.architecture_health.score);

  const gradeStyle = getGradeStyles(health.overall_grade);
  const secStyle = getGradeStyles(health.security_posture.grade);
  const archStyle = getGradeStyles(health.architecture_health.grade);

  // SVG Circular progress math
  const RADIUS = 58;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const strokeOffset = CIRCUMFERENCE - (Math.max(0, Math.min(100, health.overall_score)) / 100) * CIRCUMFERENCE;

  // Analysis engine stages (completed since we have health data)
  const engineStages: { label: string; status: 'complete' | 'running' | 'pending'; icon: string }[] = [
    { label: 'Dependency Graph', status: 'complete', icon: '⟁' },
    { label: 'Security Rules', status: 'complete', icon: '⊘' },
    { label: 'Architecture', status: 'complete', icon: '◎' },
    { label: 'Data Flow', status: 'complete', icon: '⟿' },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
      {/* ═══════ LEFT: Health Score Panel ═══════ */}
      <div className="lg:col-span-8 relative panel-elevated p-6 space-y-5 overflow-hidden">
        {/* Subtle Ambient Radial Glow behind the hero ring */}
        <div
          className="absolute -top-16 -left-16 w-72 h-72 rounded-full pointer-events-none blur-3xl opacity-15"
          style={{ backgroundColor: gradeStyle.strokeGradient[0] }}
        />

        {/* Header */}
        <div className="flex items-center space-x-3 relative z-10">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shadow-inner">
            <HeartPulse className="w-5 h-5 stroke-[2.2]" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-white tracking-tight">
                Deterministic Codebase Health Rating
              </h2>
              <span className="text-[9px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60 font-semibold">
                Phase 7 Authoritative
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              100-point composite static quality & security posture (55% Security, 45% Architecture)
            </p>
          </div>
        </div>

        {/* Main Score Area */}
        <div className="flex items-center gap-8 relative z-10">
          {/* Large Ring */}
          <div className="relative w-40 h-40 shrink-0 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 132 132">
              <defs>
                <linearGradient id="scoreRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor={gradeStyle.strokeGradient[0]} />
                  <stop offset="100%" stopColor={gradeStyle.strokeGradient[1]} />
                </linearGradient>
              </defs>

              {/* Background Track */}
              <circle
                cx="66"
                cy="66"
                r={RADIUS}
                className="stroke-slate-800/50"
                strokeWidth="8"
                fill="transparent"
              />

              {/* Progress Indicator */}
              <circle
                cx="66"
                cy="66"
                r={RADIUS}
                stroke="url(#scoreRingGradient)"
                strokeWidth="8"
                strokeDasharray={CIRCUMFERENCE}
                strokeDashoffset={strokeOffset}
                strokeLinecap="round"
                fill="transparent"
                style={{
                  transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
                  filter: `drop-shadow(0 0 8px ${gradeStyle.glow})`,
                }}
              />
            </svg>

            {/* Inner Score Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-black font-mono text-white tracking-tight leading-none">
                {animatedScore.toFixed(1)}
              </span>
              <span className="text-[10px] font-mono text-slate-500 mt-1">
                / 100
              </span>
              <div
                className={`mt-1.5 px-2.5 py-0.5 rounded-md font-black text-sm font-mono text-center border ${gradeStyle.badgeBg}`}
              >
                {health.overall_grade}
              </div>
            </div>
          </div>

          {/* Sub-scores */}
          <div className="flex-1 space-y-4">
            {/* Security Posture */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-xs font-semibold text-slate-200">Security Posture</span>
                  <span className="text-[10px] font-mono text-slate-500">(Weight: 55%)</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-black font-mono text-white">
                    {animatedSec.toFixed(1)}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono border ${secStyle.badgeBg}`}
                  >
                    Grade {health.security_posture.grade}
                  </span>
                </div>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-900/80 border border-slate-800/60 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400 transition-all duration-700 ease-out"
                  style={{ width: `${Math.max(0, Math.min(100, health.security_posture.score))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500">
                <span>Deductions: <strong className="text-slate-300">{health.security_posture.deductions.length}</strong></span>
                <span>Scale: 0 — 100</span>
              </div>
            </div>

            {/* Architecture Health */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-xs font-semibold text-slate-200">Architecture Health</span>
                  <span className="text-[10px] font-mono text-slate-500">(Weight: 45%)</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-black font-mono text-white">
                    {animatedArch.toFixed(1)}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono border ${archStyle.badgeBg}`}
                  >
                    Grade {health.architecture_health.grade}
                  </span>
                </div>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-900/80 border border-slate-800/60 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 via-blue-400 to-indigo-400 transition-all duration-700 ease-out"
                  style={{ width: `${Math.max(0, Math.min(100, health.architecture_health.score))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500">
                <span>Deductions: <strong className="text-slate-300">{health.architecture_health.deductions.length}</strong></span>
                <span>Scale: 0 — 100</span>
              </div>
            </div>
          </div>
        </div>

        {/* Authoritative Audit Summary Note */}
        {health.summary && (
          <div className="text-[11px] text-slate-300 font-mono bg-[#080C14]/50 px-4 py-2.5 rounded-lg border-l-2 border-cyan-500/60 border-r border-t border-b border-slate-800/40 flex items-start space-x-2.5 relative z-10">
            <span className="text-cyan-400 font-bold select-none">&gt;</span>
            <span className="italic leading-relaxed">"{health.summary}"</span>
          </div>
        )}
      </div>

      {/* ═══════ RIGHT: Analysis Engine Panel ═══════ */}
      <div className="lg:col-span-4 panel-elevated p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <Radio className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Analysis Engine</h3>
          </div>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 tracking-wider uppercase">
            Live
          </span>
        </div>

        {/* Engine Stages */}
        <div className="space-y-2 pt-1">
          {engineStages.map((stage, idx) => (
            <div
              key={stage.label}
              className="flex items-center justify-between py-2 px-3 rounded-lg bg-[#080C14]/40 border border-slate-800/40"
              style={{ animationDelay: `${idx * 80}ms` }}
            >
              <div className="flex items-center space-x-3">
                <span className="text-slate-500 text-sm font-mono w-5 text-center">{stage.icon}</span>
                <span className="text-xs text-slate-300 font-medium">{stage.label}</span>
              </div>
              <div className="flex items-center space-x-1.5">
                {stage.status === 'complete' && (
                  <>
                    <Check className="w-3 h-3 text-emerald-400 stroke-[3]" />
                    <span className="text-[10px] font-mono text-emerald-400 font-semibold">Complete</span>
                  </>
                )}
                {stage.status === 'running' && (
                  <>
                    <Loader2 className="w-3 h-3 text-cyan-400 animate-spin" />
                    <span className="text-[10px] font-mono text-cyan-400 font-semibold">Analyzing...</span>
                  </>
                )}
                {stage.status === 'pending' && (
                  <>
                    <Circle className="w-3 h-3 text-slate-600" />
                    <span className="text-[10px] font-mono text-slate-600">Pending</span>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Engine Progress Summary */}
        <div className="pt-2 border-t border-slate-800/50 space-y-2">
          <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-800/60 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all duration-500 ease-out"
              style={{ width: '100%' }}
            />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>Scanning repository...</span>
            <span className="text-emerald-400 font-semibold">100%</span>
          </div>
        </div>
      </div>
    </div>
  );
};
