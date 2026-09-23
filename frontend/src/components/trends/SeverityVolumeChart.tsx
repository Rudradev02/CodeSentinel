import React from 'react';

interface SeverityVolumeChartProps {
  trajectories: {
    CRITICAL: number[];
    HIGH: number[];
    MEDIUM: number[];
    LOW: number[];
    INFO: number[];
    [key: string]: number[];
  };
  dates: string[];
}

export const SeverityVolumeChart: React.FC<SeverityVolumeChartProps> = ({ trajectories, dates }) => {
  const crit = trajectories.CRITICAL || [];
  const high = trajectories.HIGH || [];
  const med = trajectories.MEDIUM || [];
  const low = trajectories.LOW || [];
  const info = trajectories.INFO || [];

  const count = dates.length;
  if (count === 0) {
    return (
      <div className="bg-[#121824]/70 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
        No severity volume history available.
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

  // Max total at any point
  const totals = Array.from({ length: count }, (_, i) => {
    return (crit[i] || 0) + (high[i] || 0) + (med[i] || 0) + (low[i] || 0) + (info[i] || 0);
  });
  const maxTotal = Math.max(5, ...totals);

  const getX = (index: number) => {
    if (count === 1) return padLeft + chartW / 2;
    return padLeft + (index / (count - 1)) * chartW;
  };

  const getY = (val: number) => {
    return padTop + (1 - val / maxTotal) * chartH;
  };

  const makeLinePath = (series: number[]) => {
    return series.map((val, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(val || 0)}`).join(' ');
  };

  return (
    <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white tracking-tight">Defect Severity Volume S_tier(t)</h3>
          <p className="text-[11px] text-slate-400">Total active findings segmented across severity tiers</p>
        </div>
        <div className="flex items-center space-x-3 text-[11px]">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
            <span className="text-slate-300">Critical ({crit[crit.length - 1] || 0})</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span className="text-slate-300">High ({high[high.length - 1] || 0})</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-400"></span>
            <span className="text-slate-300">Medium ({med[med.length - 1] || 0})</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400"></span>
            <span className="text-slate-300">Low ({low[low.length - 1] || 0})</span>
          </div>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto min-w-[500px] select-none">
          {/* Grid lines */}
          {[0, Math.round(maxTotal / 2), maxTotal].map((val) => {
            const y = getY(val);
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

          {/* Series lines */}
          {count > 1 && (
            <>
              <path d={makeLinePath(low)} fill="none" stroke="#3b82f6" strokeWidth="1.5" strokeDasharray="2 2" />
              <path d={makeLinePath(med)} fill="none" stroke="#facc15" strokeWidth="1.5" />
              <path d={makeLinePath(high)} fill="none" stroke="#f97316" strokeWidth="2" />
              <path d={makeLinePath(crit)} fill="none" stroke="#f43f5e" strokeWidth="2.5" />
            </>
          )}

          {/* X ticks */}
          {dates.map((d, i) => {
            const x = getX(i);
            const dateLabel = new Date(d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            return (
              <g key={i}>
                <line x1={x} y1={padTop + chartH} x2={x} y2={padTop + chartH + 5} stroke="#475569" strokeWidth="1" />
                <text x={x} y={padTop + chartH + 18} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
                  {dateLabel}
                </text>
                {/* Critical point */}
                <circle cx={x} cy={getY(crit[i] || 0)} r="3" fill="#f43f5e" />
                <title>{`Date: ${new Date(d).toLocaleString()}\nCritical: ${crit[i] || 0}\nHigh: ${high[i] || 0}\nMedium: ${med[i] || 0}\nLow: ${low[i] || 0}`}</title>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};
