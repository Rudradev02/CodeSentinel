import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  const sev = severity.toUpperCase();

  let colorClasses = 'bg-slate-800/80 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (sev === 'CRITICAL') {
    colorClasses = 'bg-rose-950/50 text-rose-300 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.2)]';
    dotColor = 'bg-rose-400';
  } else if (sev === 'HIGH') {
    colorClasses = 'bg-orange-950/50 text-orange-300 border-orange-500/40 shadow-[0_0_8px_rgba(249,115,22,0.15)]';
    dotColor = 'bg-orange-400';
  } else if (sev === 'MEDIUM') {
    colorClasses = 'bg-amber-950/50 text-amber-300 border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.15)]';
    dotColor = 'bg-amber-400';
  } else if (sev === 'LOW') {
    colorClasses = 'bg-blue-950/50 text-blue-300 border-blue-500/40';
    dotColor = 'bg-blue-400';
  } else if (sev === 'INFO') {
    colorClasses = 'bg-slate-800/60 text-slate-400 border-slate-700/60';
    dotColor = 'bg-slate-500';
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${colorClasses} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} mr-1.5 shrink-0`} />
      {sev}
    </span>
  );
};
