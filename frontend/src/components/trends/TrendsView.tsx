import React, { useEffect, useState } from 'react';
import {
  TrendingUp,
  Activity,
  Flame,
  CheckCircle2,
  Calendar,
  RefreshCw,
  GitBranch,
} from 'lucide-react';
import { getRepositoryTrends } from '../../api/client';
import { LongitudinalTrendDTO, RepositoryDTO } from '../../types';
import { HealthTrajectoryChart } from './HealthTrajectoryChart';
import { DefectVelocityChart } from './DefectVelocityChart';
import { SeverityVolumeChart } from './SeverityVolumeChart';
import { ComponentDriftCard } from './ComponentDriftCard';

interface TrendsViewProps {
  repository: RepositoryDTO | null;
}

export const TrendsView: React.FC<TrendsViewProps> = ({ repository }) => {
  const [trendData, setTrendData] = useState<LongitudinalTrendDTO | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedBranch, setSelectedBranch] = useState<string>('');
  const [selectedDays, setSelectedDays] = useState<number | undefined>(undefined);

  const fetchTrends = async () => {
    if (!repository) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getRepositoryTrends(repository.id, {
        branch: selectedBranch.trim() || undefined,
        days: selectedDays,
        limit: 50,
      });
      setTrendData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load longitudinal trend intelligence.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrends();
  }, [repository?.id, selectedDays]);

  if (!repository) {
    return (
      <div className="bg-[#121824]/60 border border-slate-800 rounded-2xl p-16 text-center space-y-3">
        <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 mx-auto flex items-center justify-center">
          <TrendingUp className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-bold text-white">No Repository Selected</h3>
        <p className="text-xs text-slate-400 max-w-sm mx-auto">
          Please select or register a repository to inspect its longitudinal quality trajectories and defect velocity.
        </p>
      </div>
    );
  }

  const latestPoint = trendData?.health_trajectory && trendData.health_trajectory.length > 0
    ? trendData.health_trajectory[trendData.health_trajectory.length - 1]
    : null;

  const dates = trendData?.health_trajectory.map((p) => p.created_at) || [];

  return (
    <div className="space-y-6">
      {/* Top Filter Bar */}
      <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 shadow-md">
            <TrendingUp className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white">Longitudinal Trend Intelligence</h2>
            <p className="text-[11px] text-slate-400">
              Repository: <span className="font-semibold text-slate-200">{repository.name}</span>
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-3 text-xs">
          {/* Branch Input */}
          <div className="flex items-center space-x-1.5 bg-[#141B2B] border border-slate-700/80 rounded-lg px-2.5 py-1.5">
            <GitBranch className="w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filter by branch..."
              value={selectedBranch}
              onChange={(e) => setSelectedBranch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchTrends()}
              className="bg-transparent text-slate-200 placeholder-slate-500 text-xs focus:outline-none w-32"
            />
          </div>

          {/* Time Window Buttons */}
          <div className="flex items-center bg-[#141B2B] border border-slate-700/80 rounded-lg p-0.5">
            {[
              { label: 'All Time', val: undefined },
              { label: '7d', val: 7 },
              { label: '30d', val: 30 },
              { label: '90d', val: 90 },
            ].map((opt) => (
              <button
                key={opt.label}
                onClick={() => setSelectedDays(opt.val)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all ${
                  selectedDays === opt.val
                    ? 'bg-purple-600 text-white font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Refresh Button */}
          <button
            onClick={fetchTrends}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors disabled:opacity-50"
            title="Refresh trends"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-purple-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="bg-rose-950/70 border border-rose-800 rounded-xl p-4 text-xs text-rose-200">
          {error}
        </div>
      )}

      {/* KPI Cards Row */}
      {trendData && trendData.total_snapshots > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Card 1: Total Snapshots */}
          <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-4 shadow-lg flex items-center space-x-3.5">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Calendar className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] text-slate-400 block font-medium">Timeline Snapshots</span>
              <span className="text-xl font-bold text-white tracking-tight">{trendData.total_snapshots}</span>
            </div>
          </div>

          {/* Card 2: Overall Health Delta */}
          <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-4 shadow-lg flex items-center space-x-3.5">
            <div className={`p-2.5 rounded-xl ${trendData.overall_health_delta >= 0 ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-rose-500/10 border-rose-500/20 text-rose-400'} border`}>
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] text-slate-400 block font-medium">Net Health Delta ΔH</span>
              <span className={`text-xl font-bold tracking-tight ${trendData.overall_health_delta >= 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                {trendData.overall_health_delta >= 0 ? `+${trendData.overall_health_delta}` : trendData.overall_health_delta} pts
              </span>
            </div>
          </div>

          {/* Card 3: Defect Burndown Rate */}
          <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-4 shadow-lg flex items-center space-x-3.5">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] text-slate-400 block font-medium">Defect Burndown</span>
              <span className="text-xl font-bold text-white tracking-tight">
                {(trendData.defect_burndown_rate * 100).toFixed(1)}%
              </span>
            </div>
          </div>

          {/* Card 4: Current Grade */}
          <div className="bg-[#121824]/80 border border-slate-800 rounded-2xl p-4 shadow-lg flex items-center space-x-3.5">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] text-slate-400 block font-medium">Current Posture</span>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold text-white tracking-tight">
                  {latestPoint ? latestPoint.overall_score : '—'}
                </span>
                {latestPoint && (
                  <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                    Grade {latestPoint.overall_grade}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Charts Stack */}
      {trendData && trendData.total_snapshots > 0 ? (
        <div className="space-y-6">
          <HealthTrajectoryChart points={trendData.health_trajectory} />
          <DefectVelocityChart points={trendData.defect_velocity} />
          <SeverityVolumeChart trajectories={trendData.severity_trajectories} dates={dates} />
          <ComponentDriftCard drift={trendData.component_drift} />
        </div>
      ) : (
        !loading && (
          <div className="bg-[#121824]/60 border border-slate-800 rounded-2xl p-16 text-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-slate-800/80 text-slate-400 mx-auto flex items-center justify-center">
              <Activity className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-bold text-white">No Historical Snapshots Recorded</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Run analyses on this repository using the <strong>Analyze</strong> button to generate snapshot data and establish a longitudinal trajectory.
            </p>
          </div>
        )
      )}
    </div>
  );
};
