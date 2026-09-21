import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  const sev = severity.toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  if (sev === 'CRITICAL') {
    colorClasses = 'bg-rose-950/80 text-rose-300 border-rose-800/80';
  } else if (sev === 'HIGH') {
    colorClasses = 'bg-orange-950/80 text-orange-300 border-orange-800/80';
  } else if (sev === 'MEDIUM') {
    colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-800/80';
  } else if (sev === 'LOW') {
    colorClasses = 'bg-blue-950/80 text-blue-300 border-blue-800/80';
  } else if (sev === 'INFO') {
    colorClasses = 'bg-slate-800/80 text-slate-400 border-slate-700';
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${colorClasses} ${className}`}
    >
      {sev}
    </span>
  );
};
