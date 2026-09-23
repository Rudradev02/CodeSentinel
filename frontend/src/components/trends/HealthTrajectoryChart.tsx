import React from 'react';
import { TimelinePoint } from '../../types';

interface HealthTrajectoryChartProps {
  points: TimelinePoint[];
}

export const HealthTrajectoryChart: React.FC<HealthTrajectoryChartProps> = ({ points }) => {
  if (!points || points.length === 0) {
    return (
      <div className="bg-[#121824]/70 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
        No snapshot history available to compute health trajectory.
      </div>
    );
  }

  const width = 800;
  const height = 220;
  const padLeft = 45;
  const padRight = 30;
  const padTop = 25;
  const padBottom = 35;

  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const getX = (index: number) => {
    if (points.length === 1) return padLeft + chartW / 2;
    return padLeft + (index / (points.length - 1)) * chartW;
  };

  const getY = (val: number) => {
    const clamped = Math.max(0, Math.min(100, val));
    return padTop + (1 - clamped / 100) * chartH;
  };

  // Generate SVG path strings
  const overallPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.overall_score)}`).join(' ');
  const archPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.architecture_score)}`).join(' ');
  const secPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.security_score)}`).join(' ');

  // Gradient area for overall score
  const areaPath = points.length > 1
    ? `${overallPath} L ${getX(points.length - 1)} ${padTop + chartH} L ${getX(0)} ${padTop + chartH} Z`
    : '';

  return (
    <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white tracking-tight">Codebase Health Trajectory H(t)</h3>
          <p className="text-[11px] text-slate-400">Score evolution (0–100) across historical analysis snapshots</p>
        </div>
        <div className="flex items-center space-x-4 text-[11px]">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
            <span className="text-slate-300">Composite Health</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-violet-400"></span>
            <span className="text-slate-300">Architecture</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
            <span className="text-slate-300">Security Posture</span>
          </div>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto min-w-[500px] select-none">
          <defs>
            <linearGradient id="overallGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines (0, 25, 50, 75, 100) */}
          {[0, 25, 50, 75, 100].map((score) => {
            const y = getY(score);
            return (
              <g key={score}>
                <line
                  x1={padLeft}
                  y1={y}
                  x2={width - padRight}
                  y2={y}
                  stroke="#1e293b"
                  strokeDasharray={score === 0 || score === 100 ? 'none' : '3 3'}
                  strokeWidth="1"
                />
                <text x={padLeft - 8} y={y + 3} textAnchor="end" fill="#64748b" fontSize="10" fontFamily="monospace">
                  {score}
                </text>
              </g>
            );
          })}

          {/* Area fill */}
          {areaPath && <path d={areaPath} fill="url(#overallGrad)" />}

          {/* Trajectory lines */}
          {points.length > 1 && (
            <>
              <path d={archPath} fill="none" stroke="#8b5cf6" strokeWidth="2" strokeDasharray="4 2" />
              <path d={secPath} fill="none" stroke="#06b6d4" strokeWidth="2" strokeDasharray="4 2" />
              <path d={overallPath} fill="none" stroke="#10b981" strokeWidth="2.5" />
            </>
          )}

          {/* Points */}
          {points.map((p, i) => {
            const x = getX(i);
            const y = getY(p.overall_score);
            const dateLabel = new Date(p.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            return (
              <g key={p.snapshot_id} className="group cursor-pointer">
                {/* Vertical tick line */}
                <line x1={x} y1={padTop + chartH} x2={x} y2={padTop + chartH + 5} stroke="#475569" strokeWidth="1" />
                <text x={x} y={padTop + chartH + 18} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
                  {dateLabel}
                </text>

                {/* Score point */}
                <circle cx={x} cy={y} r="4.5" fill="#10b981" stroke="#0f172a" strokeWidth="2" />
                <title>{`Date: ${new Date(p.created_at).toLocaleString()}\nScore: ${p.overall_score} (${p.overall_grade})\nArch: ${p.architecture_score} | Sec: ${p.security_score}\nFindings: ${p.total_findings}`}</title>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};
