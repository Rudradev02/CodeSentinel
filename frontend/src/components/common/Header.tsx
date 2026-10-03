import React from 'react';
import {
  Shield,
  Play,
  Loader2,
  BookOpen,
  LayoutDashboard,
  AlertTriangle,
  GitGraph,
  GitCompare,
  RotateCcw,
  History,
  TrendingUp,
  Sparkles,
  Boxes,
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
}

export const Header: React.FC<HeaderProps> = ({
  repoPath,
  onRepoPathChange,
  onRunAnalysis,
  isLoading,
  activeTab,
  onTabChange,
  onOpenRules,
  findingsCount,
  selectedRepo,
  onSelectRepo,
  onOpenHistory,
  activeSnapshotMeta,
  onExitSnapshot,
  statusOverride,
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoading && repoPath.trim()) {
      onRunAnalysis();
    }
  };

  // Authoritative system status derivation
  const systemStatus = statusOverride || (isLoading
    ? 'ANALYZING'
    : (findingsCount !== undefined || activeSnapshotMeta)
    ? 'COMPLETE'
    : 'READY');

  const navTabs = [
    { id: 'overview', label: 'Health & Overview', icon: LayoutDashboard, activeIconColor: 'text-emerald-400' },
    { id: 'findings', label: 'Findings Explorer', icon: AlertTriangle, activeIconColor: 'text-amber-400', count: findingsCount },
    { id: 'graph', label: 'Architecture Graph', icon: GitGraph, activeIconColor: 'text-emerald-400' },
    { id: 'diff', label: 'Baseline & Diff', icon: GitCompare, activeIconColor: 'text-cyan-400' },
    { id: 'trends', label: 'Trends & Velocity', icon: TrendingUp, activeIconColor: 'text-purple-400' },
    { id: 'policies', label: 'Policy Studio', icon: Sparkles, activeIconColor: 'text-cyan-400' },
    { id: 'refactoring', label: 'Refactoring Hub', icon: Boxes, activeIconColor: 'text-emerald-400' },
  ] as const;

  return (
    <header className="border-b border-slate-800/80 bg-[#0A0E17]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6">
        {/* Upper Bar */}
        <div className="h-16 flex items-center justify-between gap-4">
          {/* Logo & System Status Indicator */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="p-2 rounded-xl bg-gradient-to-br from-emerald-500/15 to-cyan-500/15 border border-emerald-500/25 text-emerald-400 shadow-md shadow-emerald-950/20">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-base tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  CodeSentinel
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 font-mono">
                  v0.1.0
                </span>

                {/* Subtle System Status Indicator */}
                {systemStatus === 'ANALYZING' && (
                  <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-cyan-950/50 text-cyan-300 border border-cyan-500/40 text-[10px] font-mono tracking-wider font-semibold">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-500"></span>
                    </span>
                    <span>◉ ANALYZING</span>
                  </span>
                )}
                {systemStatus === 'COMPLETE' && (
                  <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950/50 text-emerald-300 border border-emerald-500/30 text-[10px] font-mono tracking-wider font-semibold">
                    <Check className="w-2.5 h-2.5 text-emerald-400 stroke-[3]" />
                    <span>✓ ANALYSIS COMPLETE</span>
                  </span>
                )}
                {systemStatus === 'READY' && (
                  <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-slate-900/60 text-slate-400 border border-slate-800 text-[10px] font-mono tracking-wider">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/80"></span>
                    <span>● ENGINE READY</span>
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400">AI-Powered Intelligence, Dynamic Policies & Architecture Simulation</p>
            </div>
          </div>

          {/* Repository Selector Dropdown */}
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
          <form onSubmit={handleSubmit} className="flex-1 max-w-2xl flex items-center space-x-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={repoPath}
                onChange={(e) => onRepoPathChange(e.target.value)}
                placeholder="Enter absolute or relative repository path (e.g. analyzer/tests/fixtures/sample_project)..."
                disabled={isLoading}
                className="w-full bg-[#0D131F] border border-slate-700/70 rounded-lg px-3.5 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500/60 focus:border-emerald-500/80 transition-all disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !repoPath.trim()}
              className="inline-flex items-center space-x-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 active:scale-[0.98] text-white shadow-md shadow-emerald-950/40 hover:shadow-[0_0_14px_rgba(16,185,129,0.3)] transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed shrink-0 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>◌ Analyzing...</span>
                </>
              ) : systemStatus === 'COMPLETE' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-100 stroke-[2.5]" />
                  <span>✓ Analysis Complete</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span>▶ Analyze</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Action Navigation Buttons */}
          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={onOpenRules}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 hover:border-slate-600 transition-all cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
              <span>Rules</span>
            </button>
            <button
              onClick={onOpenHistory}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 hover:border-slate-600 transition-all cursor-pointer"
              title="View Analysis History"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>History</span>
              {selectedRepo && selectedRepo.analysis_count > 0 && (
                <span className="px-1.5 py-0.2 rounded-full bg-cyan-950 text-cyan-300 font-mono text-[10px] border border-cyan-800/80 ml-0.5 font-bold">
                  {selectedRepo.analysis_count}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Historical Snapshot Active Banner */}
        {activeSnapshotMeta && (
          <div className="py-2 px-4 mb-2 rounded-xl bg-cyan-950/40 border border-cyan-500/40 flex items-center justify-between text-xs text-cyan-200 shadow-md animate-fade-in-up">
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

        {/* Navigation Tabs Bar with Animated Indicator */}
        <div className="flex items-center space-x-1 border-t border-slate-800/60 pt-1">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id as any)}
                className={`relative inline-flex items-center space-x-2 px-3.5 py-2.5 text-xs font-semibold rounded-t-lg transition-all duration-200 cursor-pointer group ${
                  isActive
                    ? 'text-white bg-white/[0.04]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.02]'
                }`}
              >
                <Icon
                  className={`w-3.5 h-3.5 transition-colors duration-200 ${
                    isActive ? tab.activeIconColor : 'text-slate-400 group-hover:text-slate-300'
                  }`}
                />
                <span>{tab.label}</span>
                {'count' in tab && tab.count !== undefined && (
                  <span
                    className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono transition-colors ${
                      isActive
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-slate-800 text-slate-400 border border-slate-700/60'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
                {isActive && (
                  <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-400 via-cyan-400 to-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-fade-in-up" />
                )}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
