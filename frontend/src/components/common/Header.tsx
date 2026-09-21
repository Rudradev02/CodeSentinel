import React from 'react';
import {
  Shield,
  Play,
  Loader2,
  BookOpen,
  LayoutDashboard,
  AlertTriangle,
  GitGraph,
} from 'lucide-react';

interface HeaderProps {
  repoPath: string;
  onRepoPathChange: (path: string) => void;
  onRunAnalysis: () => void;
  isLoading: boolean;
  activeTab: 'overview' | 'findings' | 'graph';
  onTabChange: (tab: 'overview' | 'findings' | 'graph') => void;
  onOpenRules: () => void;
  findingsCount?: number;
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
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoading && repoPath.trim()) {
      onRunAnalysis();
    }
  };

  return (
    <header className="border-b border-slate-800 bg-[#0E1420]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6">
        {/* Upper Bar */}
        <div className="h-16 flex items-center justify-between gap-4">
          {/* Logo */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="p-2 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30 text-emerald-400 shadow-lg shadow-emerald-950/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  CodeSentinel
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                  v0.1.0 • Phase 8
                </span>
              </div>
              <p className="text-[11px] text-slate-500">Local Static Security & Architecture Auditor</p>
            </div>
          </div>

          {/* Path Input & Run Button Form */}
          <form onSubmit={handleSubmit} className="flex-1 max-w-2xl flex items-center space-x-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={repoPath}
                onChange={(e) => onRepoPathChange(e.target.value)}
                placeholder="Enter absolute or relative repository path (e.g. analyzer/tests/fixtures/sample_project)..."
                disabled={isLoading}
                className="w-full bg-[#141B2B] border border-slate-700/80 rounded-lg px-4 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500 transition-all disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !repoPath.trim()}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-950/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Analyze</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Actions */}
          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={onOpenRules}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 transition-all"
            >
              <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
              <span>Rules</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <div className="flex items-center space-x-1 border-t border-slate-800/60 pt-1">
          <button
            onClick={() => onTabChange('overview')}
            className={`inline-flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'overview'
                ? 'border-emerald-400 text-emerald-300 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Health & Overview</span>
          </button>

          <button
            onClick={() => onTabChange('findings')}
            className={`inline-flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'findings'
                ? 'border-emerald-400 text-emerald-300 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Findings Explorer</span>
            {findingsCount !== undefined && (
              <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                {findingsCount}
              </span>
            )}
          </button>

          <button
            onClick={() => onTabChange('graph')}
            className={`inline-flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
              activeTab === 'graph'
                ? 'border-emerald-400 text-emerald-300 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <GitGraph className="w-3.5 h-3.5" />
            <span>Architecture Graph</span>
          </button>
        </div>
      </div>
    </header>
  );
};
