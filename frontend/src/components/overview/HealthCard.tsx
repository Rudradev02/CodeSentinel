import React, { useEffect, useState } from 'react';
import { ShieldAlert, Cpu, HeartPulse, Award, ShieldCheck } from 'lucide-react';
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

  // SVG Circular progress math: radius 52, circumference = 2 * PI * 52 = ~326.72
  const RADIUS = 52;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const strokeOffset = CIRCUMFERENCE - (Math.max(0, Math.min(100, health.overall_score)) / 100) * CIRCUMFERENCE;

  return (
    <div className="relative bg-[#0E1524]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-6 overflow-hidden animate-fade-in-up">
      {/* Subtle Ambient Radial Glow behind the hero ring */}
      <div
        className="absolute -top-12 -right-12 w-64 h-64 rounded-full pointer-events-none blur-3xl opacity-20"
        style={{ backgroundColor: gradeStyle.strokeGradient[0] }}
      />

      {/* Hero Header + Score Visualization */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 border-b border-slate-800/80 pb-6">
        {/* Title & Metadata */}
        <div className="space-y-2">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shadow-inner">
              <HeartPulse className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white tracking-tight">
                  Deterministic Codebase Health Rating
                </h2>
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60 font-semibold">
                  Phase 7 Authoritative
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                100-point composite static quality & security posture (55% Security, 45% Architecture)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4 text-xs font-mono text-slate-400 pt-1">
            <span className="flex items-center space-x-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Security Weight: <strong className="text-white">55%</strong></span>
            </span>
            <span className="text-slate-600">•</span>
            <span className="flex items-center space-x-1.5">
              <Award className="w-3.5 h-3.5 text-cyan-400" />
              <span>Architecture Weight: <strong className="text-white">45%</strong></span>
            </span>
          </div>
        </div>

        {/* Hero Circular Score Visualization */}
        <div className="flex items-center space-x-5 bg-[#080C14]/80 px-6 py-4 rounded-xl border border-slate-800/80 shadow-inner shrink-0">
          <div className="relative w-28 h-28 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 120 120">
              <defs>
                <linearGradient id="scoreRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor={gradeStyle.strokeGradient[0]} />
                  <stop offset="100%" stopColor={gradeStyle.strokeGradient[1]} />
                </linearGradient>
              </defs>

              {/* Background Track */}
              <circle
                cx="60"
                cy="60"
                r={RADIUS}
                className="stroke-slate-800/60"
                strokeWidth="7"
                fill="transparent"
              />

              {/* Progress Indicator */}
              <circle
                cx="60"
                cy="60"
                r={RADIUS}
                stroke="url(#scoreRingGradient)"
                strokeWidth="7"
                strokeDasharray={CIRCUMFERENCE}
                strokeDashoffset={strokeOffset}
                strokeLinecap="round"
                fill="transparent"
                style={{
                  transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
                  filter: `drop-shadow(0 0 6px ${gradeStyle.glow})`,
                }}
              />
            </svg>

            {/* Inner Score Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-2xl font-black font-mono text-white tracking-tight leading-none">
                {animatedScore.toFixed(1)}
              </span>
              <span className="text-[10px] font-mono text-slate-400 mt-0.5">
                / 100
              </span>
            </div>
          </div>

          <div className="space-y-1.5 text-left border-l border-slate-800 pl-4">
            <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 font-mono">
              Composite Grade
            </p>
            <div
              className={`px-3 py-1 rounded-lg font-black text-xl font-mono text-center border shadow-sm ${gradeStyle.badgeBg}`}
            >
              {health.overall_grade}
            </div>
            <p className="text-[10px] text-slate-500 font-mono">
              Status: <span className={gradeStyle.text}>Verified</span>
            </p>
          </div>
        </div>
      </div>

      {/* Sub-Score Breakdown Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Security Posture (55%) */}
        <div className="bg-[#080C14]/80 border border-slate-800/80 rounded-xl p-4.5 space-y-3 hover:border-slate-700/80 transition-all duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <span className="text-xs font-bold text-slate-200 block">Security Posture</span>
                <span className="text-[10px] font-mono text-slate-400">Weight: 55% of Composite</span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-sm font-black font-mono text-white">
                {animatedSec.toFixed(1)}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${secStyle.badgeBg}`}
              >
                Grade {health.security_posture.grade}
              </span>
            </div>
          </div>

          {/* Technical Progress Bar */}
          <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-800/80 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400 transition-all duration-700 ease-out"
              style={{ width: `${Math.max(0, Math.min(100, health.security_posture.score))}%` }}
            />
          </div>

          <div className="flex justify-between items-center text-[11px] font-mono text-slate-400 pt-0.5">
            <span>Deductions: <strong className="text-slate-200">{health.security_posture.deductions.length}</strong></span>
            <span>Scale: 0 — 100 pts</span>
          </div>
        </div>

        {/* Architecture Health (45%) */}
        <div className="bg-[#080C14]/80 border border-slate-800/80 rounded-xl p-4.5 space-y-3 hover:border-slate-700/80 transition-all duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <Cpu className="w-4 h-4" />
              </div>
              <div>
                <span className="text-xs font-bold text-slate-200 block">Architecture Health</span>
                <span className="text-[10px] font-mono text-slate-400">Weight: 45% of Composite</span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-sm font-black font-mono text-white">
                {animatedArch.toFixed(1)}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${archStyle.badgeBg}`}
              >
                Grade {health.architecture_health.grade}
              </span>
            </div>
          </div>

          {/* Technical Progress Bar */}
          <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-800/80 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 via-blue-400 to-indigo-400 transition-all duration-700 ease-out"
              style={{ width: `${Math.max(0, Math.min(100, health.architecture_health.score))}%` }}
            />
          </div>

          <div className="flex justify-between items-center text-[11px] font-mono text-slate-400 pt-0.5">
            <span>Deductions: <strong className="text-slate-200">{health.architecture_health.deductions.length}</strong></span>
            <span>Scale: 0 — 100 pts</span>
          </div>
        </div>
      </div>

      {/* Authoritative Audit Summary Note */}
      {health.summary && (
        <div className="text-xs text-slate-300 font-mono bg-[#080C14]/60 px-4 py-3 rounded-lg border-l-2 border-emerald-500 border-r border-t border-b border-slate-800/60 flex items-start space-x-2.5">
          <span className="text-emerald-400 font-bold select-none">&gt;</span>
          <span className="italic leading-relaxed">"{health.summary}"</span>
        </div>
      )}
    </div>
  );
};

