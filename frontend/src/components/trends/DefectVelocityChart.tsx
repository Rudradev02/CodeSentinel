import React from 'react';
import { DefectVelocityPoint } from '../../types';

interface DefectVelocityChartProps {
  points: DefectVelocityPoint[];
}

export const DefectVelocityChart: React.FC<DefectVelocityChartProps> = ({ points }) => {
  if (!points || points.length === 0) {
    return (
      <div className="bg-[#121824]/70 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
        No defect velocity history available.
      </div>
    );
  }

  const width = 800;
  const height = 200;
  const padLeft = 45;
  const padRight = 30;
  const padTop = 20;
  const padBottom = 35;

  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const maxVal = Math.max(
    5,
    ...points.map((p) => Math.max(p.new_defects, p.resolved_defects))
  );

  const getX = (index: number) => {
    const slotW = chartW / points.length;
    return padLeft + index * slotW + slotW / 2;
  };

  const getYHeight = (val: number) => {
    return (val / maxVal) * chartH;
  };

  return (
    <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white tracking-tight">Defect Velocity & Churn ΔD(t)</h3>
          <p className="text-[11px] text-slate-400">Newly introduced vs. resolved defects per analysis run</p>
        </div>
        <div className="flex items-center space-x-4 text-[11px]">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500"></span>
            <span className="text-slate-300">New Defects</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500"></span>
            <span className="text-slate-300">Resolved Defects</span>
          </div>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto min-w-[500px] select-none">
          {/* Grid lines */}
          {[0, Math.round(maxVal / 2), maxVal].map((val) => {
            const y = padTop + chartH - getYHeight(val);
            return (
              <g key={val}>
                <line
                  x1={padLeft}
                  y1={y}
                  x2={width - padRight}
                  y2={y}
                  stroke="#1e293b"
                  strokeDasharray={val === 0 ? 'none' : '3 3'}
                  strokeWidth="1"
                />
                <text x={padLeft - 8} y={y + 3} textAnchor="end" fill="#64748b" fontSize="10" fontFamily="monospace">
                  {val}
                </text>
              </g>
            );
          })}

          {/* Bars */}
          {points.map((p, i) => {
            const centerX = getX(i);
            const slotW = chartW / points.length;
            const barW = Math.min(18, Math.max(6, slotW * 0.28));

            const newH = getYHeight(p.new_defects);
            const newY = padTop + chartH - newH;

            const resH = getYHeight(p.resolved_defects);
            const resY = padTop + chartH - resH;

            const dateLabel = new Date(p.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

            return (
              <g key={p.snapshot_id} className="cursor-pointer">
                {/* New Defects Bar (Red/Rose) */}
                <rect
                  x={centerX - barW - 2}
                  y={newY}
                  width={barW}
                  height={Math.max(1, newH)}
                  fill="#f43f5e"
                  rx="2"
                  opacity="0.9"
                />

                {/* Resolved Defects Bar (Emerald) */}
                <rect
                  x={centerX + 2}
                  y={resY}
                  width={barW}
                  height={Math.max(1, resH)}
                  fill="#10b981"
                  rx="2"
                  opacity="0.9"
                />

                {/* X axis tick & date */}
                <line x1={centerX} y1={padTop + chartH} x2={centerX} y2={padTop + chartH + 5} stroke="#475569" strokeWidth="1" />
                <text x={centerX} y={padTop + chartH + 18} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
                  {dateLabel}
                </text>

                <title>{`Date: ${new Date(p.created_at).toLocaleString()}\nNew: +${p.new_defects}\nResolved: -${p.resolved_defects}\nNet: ${p.net_change > 0 ? '+' + p.net_change : p.net_change}`}</title>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};
