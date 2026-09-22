import React, { useEffect, useState } from 'react';
import {
  X,
  Clock,
  GitCommit,
  GitBranch,
  Shield,
  Layers,
  ArrowRight,
  Loader2,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  History,
} from 'lucide-react';
import { getHistoricalAnalysis, listRepositoryAnalyses } from '../../api/client';
import {
  AnalysisResultDTO,
  AnalysisSnapshotSummaryDTO,
  RepositoryDTO,
} from '../../types';

interface AnalysisHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  repository: RepositoryDTO | null;
  onSelectSnapshot: (result: AnalysisResultDTO, summary: AnalysisSnapshotSummaryDTO) => void;
  currentLoadedSnapshotId?: string | null;
}

export const AnalysisHistoryModal: React.FC<AnalysisHistoryModalProps> = ({
  isOpen,
  onClose,
  repository,
  onSelectSnapshot,
  currentLoadedSnapshotId,
}) => {
  const [snapshots, setSnapshots] = useState<AnalysisSnapshotSummaryDTO[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [skip, setSkip] = useState<number>(0);
  const limit = 10;
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async (offset = skip) => {
    if (!repository) return;
    setLoading(true);
    setError(null);
    try {
      const data = await listRepositoryAnalyses(repository.id, offset, limit);
      setSnapshots(data.items);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch analysis history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && repository) {
      setSkip(0);
      fetchHistory(0);
    }
  }, [isOpen, repository?.id]);

  if (!isOpen || !repository) return null;

  const handleLoadSnapshot = async (summary: AnalysisSnapshotSummaryDTO) => {
    setLoadingId(summary.id);
    try {
      const fullResult = await getHistoricalAnalysis(repository.id, summary.id);
      onSelectSnapshot(fullResult, summary);
      onClose();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to load historical snapshot');
    } finally {
      setLoadingId(null);
    }
  };

  const getGradeBadge = (grade: string) => {
    const colors: Record<string, string> = {
      A: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
      B: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
      C: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
      D: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
      F: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
    };
    return colors[grade] || 'bg-slate-800 text-slate-300 border-slate-700';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-[#101726] border border-slate-700/80 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between shrink-0 bg-[#0E1422]">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white">Immutable Analysis History</h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                  {repository.name}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Browse and inspect historical, immutable static analysis snapshots.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {error && (
            <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div className="py-16 flex flex-col items-center justify-center space-y-3 text-slate-400">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              <span className="text-xs">Loading immutable analysis history...</span>
            </div>
          ) : snapshots.length === 0 ? (
            <div className="py-16 text-center space-y-3">
              <Clock className="w-8 h-8 text-slate-600 mx-auto" />
              <div className="text-sm font-semibold text-slate-300">No Analysis Snapshots Recorded</div>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                No historical snapshots have been persisted for this repository yet. Run analysis to create the first immutable audit snapshot.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {snapshots.map((item) => {
                const isCurrent = currentLoadedSnapshotId === item.id;
                const formattedDate = new Date(item.created_at).toLocaleString();
                const shortId = item.id.slice(0, 8);

                return (
                  <div
                    key={item.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isCurrent
                        ? 'bg-cyan-950/20 border-cyan-500/50 shadow-lg shadow-cyan-950/20'
                        : 'bg-[#141C2E]/70 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      {/* Left: Metadata & Grade */}
                      <div className="space-y-2 flex-1">
                        <div className="flex items-center space-x-2.5">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getGradeBadge(item.overall_grade)}`}>
                            Grade {item.overall_grade} ({item.overall_score.toFixed(1)})
                          </span>
                          <span className="text-xs font-semibold text-white">
                            Snapshot #{shortId}
                          </span>
                          <span className="text-[11px] text-slate-400 flex items-center space-x-1">
                            <Clock className="w-3 h-3 text-slate-500 inline" />
                            <span>{formattedDate}</span>
                          </span>
                          {isCurrent && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                              Active View
                            </span>
                          )}
                        </div>

                        {/* Provenance & Sub-scores */}
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          {/* Git details */}
                          {item.branch && (
                            <span className="inline-flex items-center space-x-1 text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                              <GitBranch className="w-3 h-3 text-emerald-400" />
                              <span>{item.branch}</span>
                            </span>
                          )}
                          {item.commit_hash && (
                            <span className="inline-flex items-center space-x-1 text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 font-mono text-[11px]">
                              <GitCommit className="w-3 h-3 text-cyan-400" />
                              <span>{item.commit_hash.slice(0, 7)}</span>
                            </span>
                          )}
                          {item.is_dirty !== null && item.is_dirty !== undefined && (
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                                item.is_dirty
                                  ? 'bg-amber-950/40 text-amber-400 border-amber-800/60'
                                  : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60'
                              }`}
                            >
                              {item.is_dirty ? 'DIRTY' : 'CLEAN'}
                            </span>
                          )}

                          {/* Sub-scores */}
                          <span className="inline-flex items-center space-x-1 text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                            <Layers className="w-3 h-3 text-indigo-400" />
                            <span>Arch: {item.architecture_score.toFixed(1)} ({item.architecture_grade})</span>
                          </span>
                          <span className="inline-flex items-center space-x-1 text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                            <Shield className="w-3 h-3 text-emerald-400" />
                            <span>Sec: {item.security_score.toFixed(1)} ({item.security_grade})</span>
                          </span>
                          <span className="text-[11px] text-slate-500 font-mono">
                            {item.duration_seconds.toFixed(2)}s
                          </span>
                        </div>

                        {/* Finding counters */}
                        <div className="flex items-center space-x-2 pt-0.5 text-[11px]">
                          <span className="text-slate-400">Findings ({item.total_findings}):</span>
                          {item.critical_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 font-semibold border border-rose-800">
                              {item.critical_count} crit
                            </span>
                          )}
                          {item.high_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-orange-950 text-orange-300 font-semibold border border-orange-800">
                              {item.high_count} high
                            </span>
                          )}
                          {item.medium_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 font-semibold border border-amber-800">
                              {item.medium_count} med
                            </span>
                          )}
                          {item.low_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-blue-950 text-blue-300 font-semibold border border-blue-800">
                              {item.low_count} low
                            </span>
                          )}
                          {item.total_findings === 0 && (
                            <span className="text-emerald-400 font-semibold">0 issues found</span>
                          )}
                        </div>
                      </div>

                      {/* Right: Load Snapshot Button */}
                      <button
                        onClick={() => handleLoadSnapshot(item)}
                        disabled={loadingId === item.id}
                        className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 transition-all shrink-0"
                      >
                        {loadingId === item.id ? (
                          <>
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                            <span>Loading...</span>
                          </>
                        ) : (
                          <>
                            <span>Inspect Snapshot</span>
                            <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Modal Footer: Pagination */}
        {total > limit && (
          <div className="p-4 border-t border-slate-800 bg-[#0E1422] flex items-center justify-between text-xs text-slate-400 shrink-0">
            <span>
              Showing {skip + 1} - {Math.min(skip + limit, total)} of {total} snapshots
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => {
                  const newSkip = Math.max(0, skip - limit);
                  setSkip(newSkip);
                  fetchHistory(newSkip);
                }}
                disabled={skip === 0 || loading}
                className="p-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => {
                  const newSkip = skip + limit;
                  if (newSkip < total) {
                    setSkip(newSkip);
                    fetchHistory(newSkip);
                  }
                }}
                disabled={skip + limit >= total || loading}
                className="p-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
