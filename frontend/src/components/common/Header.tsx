import React from 'react';
import {
  Play,
  Loader2,
  BookOpen,
  RotateCcw,
  History,
  Check,
} from 'lucide-react';
import { AnalysisSnapshotSummaryDTO, RepositoryDTO } from '../../types';
import { RepositorySelector } from './RepositorySelector';

interface HeaderProps {
  repoPath: string;
  onRepoPathChange: (path: string) => void;
  onRunAnalysis: () => void;
  isLoading: boolean;
  activeTab: 'overview' | 'findings' | 'graph' | 'diff' | 'trends' | 'policies' | 'refactoring';
  onTabChange: (tab: 'overview' | 'findings' | 'graph' | 'diff' | 'trends' | 'policies' | 'refactoring') => void;
  onOpenRules: () => void;
  findingsCount?: number;
  selectedRepo: RepositoryDTO | null;
  onSelectRepo: (repo: RepositoryDTO | null) => void;
  onOpenHistory: () => void;
  activeSnapshotMeta?: AnalysisSnapshotSummaryDTO | null;
  onExitSnapshot?: () => void;
  statusOverride?: 'READY' | 'ANALYZING' | 'COMPLETE';
  systemStatus?: string;
}

export const Header: React.FC<HeaderProps> = ({
  repoPath,
  onRepoPathChange,
  onRunAnalysis,
  isLoading,
  onOpenRules,
  selectedRepo,
  onSelectRepo,
  onOpenHistory,
  activeSnapshotMeta,
  onExitSnapshot,
  systemStatus: systemStatusProp,
  statusOverride,
  findingsCount,
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoading && repoPath.trim()) {
      onRunAnalysis();
    }
  };

  // Authoritative system status derivation
  const systemStatus = statusOverride || systemStatusProp || (isLoading
    ? 'ANALYZING'
    : (findingsCount !== undefined || activeSnapshotMeta)
    ? 'COMPLETE'
    : 'READY');

  return (
    <header className="border-b border-slate-800/60 bg-[#0A0E17]/95 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-[1400px] mx-auto px-6">
        {/* Single Compact Top Bar */}
        <div className="h-14 flex items-center justify-between gap-4">
          {/* Repository Selector */}
          <div className="shrink-0">
            <RepositorySelector
              selectedRepo={selectedRepo}
              onSelectRepo={(repo) => {
                onSelectRepo(repo);
                if (repo) {
                  onRepoPathChange(repo.path);
                }
              }}
              onOpenHistory={onOpenHistory}
            />
          </div>

          {/* Path Input & Primary Run Button */}
          <form onSubmit={handleSubmit} className="flex-1 max-w-xl flex items-center space-x-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={repoPath}
                onChange={(e) => onRepoPathChange(e.target.value)}
                placeholder="Enter repository path (e.g. analyzer/tests/fixtures/sample_project)..."
                disabled={isLoading}
                className="w-full bg-[#0D131F] border border-slate-700/60 rounded-lg px-3.5 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/60 focus:border-cyan-500/60 transition-all disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !repoPath.trim()}
              className="inline-flex items-center space-x-1.5 px-5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 active:scale-[0.98] text-white shadow-md shadow-emerald-950/40 hover:shadow-[0_0_14px_rgba(16,185,129,0.3)] transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed shrink-0 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : systemStatus === 'COMPLETE' ? (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span>Analyze</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span>Analyze</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Action Buttons */}
          <div className="flex items-center space-x-1.5 shrink-0">
            <button
              onClick={onOpenRules}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/40 hover:border-slate-600 transition-all cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
              <span>Rules</span>
            </button>
            <button
              onClick={onOpenHistory}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/40 hover:border-slate-600 transition-all cursor-pointer"
              title="View Analysis History"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>History</span>
              {selectedRepo && selectedRepo.analysis_count > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 font-mono text-[10px] border border-cyan-800/60 font-bold">
                  {selectedRepo.analysis_count}
                </span>
              )}
            </button>

            {/* Engine Status Indicator */}
            <div className="ml-1.5 pl-2 border-l border-slate-800/60">
              {systemStatus === 'ANALYZING' && (
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/40 text-cyan-300 border border-cyan-500/30 text-[10px] font-mono tracking-wider font-semibold">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-500"></span>
                  </span>
                  <span>ANALYZING</span>
                </span>
              )}
              {systemStatus === 'COMPLETE' && (
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-emerald-950/40 text-emerald-300 border border-emerald-500/25 text-[10px] font-mono tracking-wider font-semibold">
                  <Check className="w-3 h-3 text-emerald-400 stroke-[2.5]" />
                  <span>COMPLETE</span>
                </span>
              )}
              {systemStatus === 'READY' && (
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-slate-900/50 text-slate-400 border border-slate-800 text-[10px] font-mono tracking-wider">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/80"></span>
                  <span>ENGINE READY</span>
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Historical Snapshot Active Banner */}
        {activeSnapshotMeta && (
          <div className="py-2 px-4 mb-2 rounded-xl bg-cyan-950/30 border border-cyan-500/30 flex items-center justify-between text-xs text-cyan-200 shadow-md animate-fade-in-up">
            <div className="flex items-center space-x-2.5">
              <History className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="font-semibold text-white">Historical Snapshot:</strong> #{activeSnapshotMeta.id.slice(0, 8)} • Recorded {new Date(activeSnapshotMeta.created_at).toLocaleString()} • Read-Only
              </span>
            </div>
            {onExitSnapshot && (
              <button
                onClick={onExitSnapshot}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 text-[11px] font-medium transition-colors cursor-pointer"
              >
                <RotateCcw className="w-3 h-3 text-cyan-400" />
                <span>Exit Historical View</span>
              </button>
            )}
          </div>
        )}
      </div>
    </header>
  );
};
