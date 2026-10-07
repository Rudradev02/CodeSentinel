import React, { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  FolderSearch,
  Shield,
  LayoutDashboard,
  AlertTriangle,
  GitGraph,
  GitCompare,
  TrendingUp,
  Sparkles,
  Boxes,
  Wrench,
  ChevronRight,
  Eye,
} from 'lucide-react';
import {
  analyzeRepository,
  CodeSentinelAPIError,
  getHistoricalAnalysis,
  getRepository,
  persistExternalSnapshot,
  registerRepository,
  runRepositoryAnalysis,
} from './api/client';
import { useJobProgress } from './services/useJobProgress';
import { Header } from './components/common/Header';
import { LoadingState } from './components/common/LoadingState';
import { MetricSummary } from './components/overview/MetricSummary';
import { HealthCard } from './components/overview/HealthCard';
import { DeductionsTable } from './components/overview/DeductionsTable';
import { FindingsExplorer } from './components/findings/FindingsExplorer';
import { ArchitectureGraph } from './components/architecture/ArchitectureGraph';
import { DifferentialView } from './components/differential/DifferentialView';
import { TrendsView } from './components/trends/TrendsView';
import { PolicyStudio } from './components/policies/PolicyStudio';
import { RefactoringHub } from './components/architecture/RefactoringHub';
import { RuleCatalogModal } from './components/rules/RuleCatalogModal';
import { AnalysisHistoryModal } from './components/common/AnalysisHistoryModal';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import {
  AnalysisResultDTO,
  AnalysisSnapshotSummaryDTO,
  RepositoryDTO,
} from './types';

export const App: React.FC = () => {
  const [repoPath, setRepoPath] = useState<string>('analyzer/tests/fixtures/sample_project');
  const [selectedRepo, setSelectedRepo] = useState<RepositoryDTO | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResultDTO | null>(null);
  const [liveAnalysisResult, setLiveAnalysisResult] = useState<AnalysisResultDTO | null>(null);
  const [activeSnapshotMeta, setActiveSnapshotMeta] = useState<AnalysisSnapshotSummaryDTO | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<{ code?: string; message: string } | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'graph' | 'diff' | 'trends' | 'policies' | 'refactoring'>('overview');
  const [rulesModalOpen, setRulesModalOpen] = useState<boolean>(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [historyModalOpen, setHistoryModalOpen] = useState<boolean>(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [analysisCompleted, setAnalysisCompleted] = useState<boolean>(false);

  const selectedRepoRef = useRef<RepositoryDTO | null>(selectedRepo);
  const isAnalyzingRef = useRef<boolean>(false);
  const activeJobRepoIdRef = useRef<string | null>(null);
  useEffect(() => {
    selectedRepoRef.current = selectedRepo;
  }, [selectedRepo]);

  // Hook for streaming worker progress via Server-Sent Events (SSE)
  const {
    progressPercent,
    progressStage,
    progressMessage,
    cancel: cancelActiveJob,
  } = useJobProgress(activeJobId, {
    onCompleted: async (snapshotId: string, repositoryId?: string) => {
      try {
        setAnalysisCompleted(true);
        let repo: RepositoryDTO | null = null;
        const targetRepoId = repositoryId || activeJobRepoIdRef.current;
        if (targetRepoId) {
          try {
            repo = await getRepository(targetRepoId);
          } catch {
            // Ignore lookup error
          }
        }
        if (!repo) {
          repo = selectedRepoRef.current || selectedRepo;
        }
        if (!repo && repoPath.trim()) {
          try {
            const registered = await registerRepository(repoPath.trim());
            repo = registered;
          } catch {
            // Fallback
          }
        }
        if (repo) {
          setSelectedRepo(repo);
          selectedRepoRef.current = repo;
          const snapshot = await getHistoricalAnalysis(repo.id, snapshotId);
          await new Promise((r) => setTimeout(r, 400));
          setAnalysisResult(snapshot);
          setLiveAnalysisResult(snapshot);
          setActiveSnapshotMeta(null);
          try {
            const fresh = await getRepository(repo.id);
            setSelectedRepo(fresh);
            selectedRepoRef.current = fresh;
          } catch {
            // Ignore refresh error
          }
        }
      } catch (err) {
        setError({
          code: 'SNAPSHOT_LOAD_FAILED',
          message: err instanceof Error ? err.message : 'Failed to load completed snapshot from storage.',
        });
      } finally {
        activeJobRepoIdRef.current = null;
        setLoading(false);
        setActiveJobId(null);
        setAnalysisCompleted(false);
      }
    },
    onFailed: (errMsg: string) => {
      setError({
        code: 'ANALYSIS_FAILED',
        message: errMsg,
      });
      setLoading(false);
      setActiveJobId(null);
      setAnalysisCompleted(false);
    },
    onCancelled: () => {
      setLoading(false);
      setActiveJobId(null);
      setAnalysisCompleted(false);
    },
  });

  // Auto-recover loading state if stalled for > 45s
  useEffect(() => {
    if (!loading) return;
    const timer = setTimeout(() => {
      setLoading(false);
      setActiveJobId(null);
      setAnalysisCompleted(false);
    }, 45000);
    return () => clearTimeout(timer);
  }, [loading]);

  const handleRunAnalysis = async (targetPath = repoPath) => {
    if (!targetPath.trim() || isAnalyzingRef.current) return;
    isAnalyzingRef.current = true;

    setLoading(true);
    setError(null);

    try {
      let repo = selectedRepo;
      // Auto-register repository if path is not yet registered or changed
      try {
        repo = await registerRepository(targetPath.trim());
        setSelectedRepo(repo);
        selectedRepoRef.current = repo;
        activeJobRepoIdRef.current = repo.id;
      } catch {
        // Fall back to existing or direct analysis if repo registration fails
      }

      if (repo) {
        activeJobRepoIdRef.current = repo.id;
        try {
          // Phase 11: Async Analysis Job via Celery Worker (202 Accepted)
          const job = await runRepositoryAnalysis(repo.id);
          if (job.status === 'COMPLETED' && job.snapshot_id) {
            // Instant completion (e.g. cached snapshot)
            setAnalysisCompleted(true);
            const snapshot = await getHistoricalAnalysis(repo.id, job.snapshot_id);
            await new Promise((r) => setTimeout(r, 600));
            setAnalysisResult(snapshot);
            setLiveAnalysisResult(snapshot);
            setActiveSnapshotMeta(null);
            setLoading(false);
            setAnalysisCompleted(false);
            activeJobRepoIdRef.current = null;
          } else {
            // Begin SSE tracking for the active job
            activeJobRepoIdRef.current = repo.id;
            setActiveJobId(job.id);
          }
        } catch (jobErr) {
          console.warn('Background worker unavailable, falling back to direct analysis:', jobErr);
          const data = await analyzeRepository(targetPath);
          setAnalysisCompleted(true);
          await new Promise((r) => setTimeout(r, 600));
          setAnalysisResult(data);
          setLiveAnalysisResult(data);
          setActiveSnapshotMeta(null);

          if (repo) {
            try {
              const persisted = await persistExternalSnapshot(repo.id, data);
              if (persisted) {
                setAnalysisResult(persisted);
                setLiveAnalysisResult(persisted);
              }
              const freshRepo = await getRepository(repo.id);
              setSelectedRepo(freshRepo);
            } catch (err) {
              console.warn('Could not persist snapshot to database:', err);
            }
          }
          setLoading(false);
          setAnalysisCompleted(false);
        }
      } else {
        // Fallback to legacy sync analysis
        const data = await analyzeRepository(targetPath);
        setAnalysisCompleted(true);
        await new Promise((r) => setTimeout(r, 600));
        setAnalysisResult(data);
        setLiveAnalysisResult(data);
        setActiveSnapshotMeta(null);
        try {
          const registered = await registerRepository(targetPath.trim());
          setSelectedRepo(registered);
          try {
            const persisted = await persistExternalSnapshot(registered.id, data);
            if (persisted) {
              setAnalysisResult(persisted);
              setLiveAnalysisResult(persisted);
            }
          } catch (pErr) {
            console.warn('Could not persist snapshot to database:', pErr);
          }
        } catch {
          // Fallback gracefully
        }
        setLoading(false);
        setAnalysisCompleted(false);
      }
    } catch (err) {
      setLoading(false);
      setAnalysisCompleted(false);
      if (err instanceof CodeSentinelAPIError) {
        setError({
          code: err.code,
          message: err.message,
        });
      } else {
        setError({
          code: 'UNEXPECTED_ERROR',
          message: err instanceof Error ? err.message : 'Analysis failed to complete.',
        });
      }
      setLoading(false);
      setActiveJobId(null);
    } finally {
      isAnalyzingRef.current = false;
    }
  };

  // Auto-run analysis on fixture on initial load
  useEffect(() => {
    handleRunAnalysis('analyzer/tests/fixtures/sample_project');
  }, []);

  const handleOpenRule = (ruleId: string) => {
    setSelectedRuleId(ruleId);
    setRulesModalOpen(true);
  };

  // Collect all deductions from architecture and security sub-scores
  const allDeductions = [
    ...(analysisResult?.health?.architecture_health.deductions || []),
    ...(analysisResult?.health?.security_posture.deductions || []),
  ];

  // Authoritative system status derivation
  const systemStatus = loading
    ? 'ANALYZING'
    : (analysisResult || activeSnapshotMeta)
    ? 'COMPLETE'
    : 'READY';

  const navTabs = [
    { id: 'overview' as const, label: 'Health & Overview', icon: LayoutDashboard, activeColor: 'text-emerald-400' },
    { id: 'findings' as const, label: 'Findings Explorer', icon: AlertTriangle, activeColor: 'text-amber-400', count: analysisResult?.findings.length },
    { id: 'graph' as const, label: 'Architecture Graph', icon: GitGraph, activeColor: 'text-cyan-400' },
    { id: 'diff' as const, label: 'Baseline & Diff', icon: GitCompare, activeColor: 'text-cyan-400' },
    { id: 'trends' as const, label: 'Trends & Velocity', icon: TrendingUp, activeColor: 'text-purple-400' },
    { id: 'policies' as const, label: 'Policy Studio', icon: Sparkles, activeColor: 'text-purple-400' },
    { id: 'refactoring' as const, label: 'Refactoring Hub', icon: Boxes, activeColor: 'text-emerald-400' },
  ];

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex font-sans selection:bg-cyan-500/30 selection:text-white">
      {/* ═══════════════════════════════════════════════════
          SIDEBAR NAVIGATION
          ═══════════════════════════════════════════════════ */}
      <aside className="w-56 shrink-0 bg-[#0A0E17] border-r border-slate-800/60 flex flex-col h-screen sticky top-0 z-40">
        {/* Logo */}
        <div className="px-4 pt-5 pb-4">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-gradient-to-br from-emerald-500/15 to-cyan-500/15 border border-emerald-500/25 text-emerald-400 shadow-md shadow-emerald-950/20">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-extrabold text-sm tracking-tight text-white">
                  CodeSentinel
                </span>
                <span className="text-[9px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 font-mono">
                  v1.0.0
                </span>
              </div>
              <p className="text-[10px] text-slate-500 mt-0.5 leading-tight">
                AI-Powered Intelligence, Dynamic Policies & Architecture Simulation
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 px-3 py-2 space-y-0.5 sidebar-nav overflow-y-auto">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative w-full flex items-center space-x-2.5 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 cursor-pointer group ${
                  isActive
                    ? 'nav-item-active text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
                }`}
              >
                <Icon
                  className={`w-4 h-4 transition-colors duration-200 shrink-0 ${
                    isActive ? tab.activeColor : 'text-slate-500 group-hover:text-slate-400'
                  }`}
                />
                <span className="truncate">{tab.label}</span>
                {'count' in tab && tab.count !== undefined && tab.count > 0 && (
                  <span
                    className={`ml-auto px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold shrink-0 ${
                      isActive
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-slate-800 text-slate-400 border border-slate-700/60'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="px-3 pb-4 pt-2 mt-auto">
          <div className="sidebar-footer-badge px-3 py-3 space-y-2">
            <div className="flex items-center space-x-2">
              <Wrench className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-[11px] font-semibold text-slate-300">Built for Developers</span>
            </div>
            <div className="flex items-center space-x-3 text-[10px] text-slate-500 font-mono">
              <span>Secure</span>
              <ChevronRight className="w-2.5 h-2.5" />
              <span>Analyze</span>
              <ChevronRight className="w-2.5 h-2.5" />
              <span>Improve</span>
            </div>
          </div>
          <p className="text-[10px] text-slate-600 font-mono mt-2.5 px-1">CodeSentinel v1.0.0</p>
        </div>
      </aside>

      {/* ═══════════════════════════════════════════════════
          MAIN CONTENT AREA
          ═══════════════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col min-h-screen bg-technical-grid ambient-glow-top relative overflow-x-hidden">
        {/* Top Header Bar */}
        <Header
          repoPath={repoPath}
          onRepoPathChange={setRepoPath}
          onRunAnalysis={() => handleRunAnalysis(repoPath)}
          isLoading={loading}
          activeTab={activeTab}
          onTabChange={setActiveTab}
          onOpenRules={() => {
            setSelectedRuleId(null);
            setRulesModalOpen(true);
          }}
          findingsCount={analysisResult?.findings.length}
          selectedRepo={selectedRepo}
          onSelectRepo={(repo) => {
            setSelectedRepo(repo);
            if (repo) {
              setRepoPath(repo.path);
            }
          }}
          onOpenHistory={() => setHistoryModalOpen(true)}
          activeSnapshotMeta={activeSnapshotMeta}
          onExitSnapshot={() => {
            setAnalysisResult(liveAnalysisResult);
            setActiveSnapshotMeta(null);
          }}
          systemStatus={systemStatus}
        />

        {/* Main Content */}
        <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-5 space-y-5 relative z-10">
          {/* Error Banner */}
          {error && (
            <div className="bg-rose-950/70 border border-rose-800/80 rounded-xl p-4 flex items-start space-x-3.5 shadow-lg animate-fade-in-up">
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-rose-900/80 text-rose-200 border border-rose-700/60">
                    {error.code || 'API_ERROR'}
                  </span>
                  <span className="text-sm font-semibold text-white">Analysis Operation Failed</span>
                </div>
                <p className="text-xs text-rose-200/90 leading-relaxed font-mono">{error.message}</p>
              </div>
            </div>
          )}

          {/* Loading Indicator */}
          {loading && (
            <LoadingState
              targetPath={repoPath}
              message={progressMessage}
              progressPercent={progressPercent}
              stage={progressStage}
              isCompleted={analysisCompleted}
              onCancel={activeJobId ? cancelActiveJob : undefined}
            />
          )}

          {/* Active Analysis Dashboard */}
          {!loading && analysisResult && (
            <>
              {activeTab === 'overview' && (
                <div className="space-y-5">
                  {/* Repository Context Banner */}
                  <div className="animate-fade-in-up">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="section-header mb-1.5 flex items-center space-x-2">
                          <Eye className="w-3 h-3" />
                          <span>CODE ANALYSIS</span>
                        </div>
                        <h1 className="text-xl font-bold text-white tracking-tight">
                          Repository Overview
                        </h1>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Comprehensive analysis of your codebase security, architecture and quality posture.
                        </p>
                      </div>
                      {/* Repo Context Card */}
                      <div className="panel px-5 py-3 flex items-center space-x-6">
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <FolderSearch className="w-3.5 h-3.5 text-cyan-400" />
                            <span className="text-xs font-bold text-white">{selectedRepo?.name || 'sample_project'}</span>
                          </div>
                          <p className="text-[10px] font-mono text-slate-500 truncate max-w-[280px]">
                            {selectedRepo?.path || repoPath}
                          </p>
                        </div>
                        <div className="flex items-center space-x-4 text-[11px] font-mono text-slate-400 border-l border-slate-800 pl-4">
                          <span><strong className="text-white">{analysisResult.summary.total_files}</strong> Files</span>
                          <span><strong className="text-white">{analysisResult.summary.total_loc}</strong> LOC</span>
                          <span><strong className="text-white">{analysisResult.summary.total_modules}</strong> Modules</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="animate-fade-in-up delay-1">
                    <MetricSummary
                      summary={analysisResult.summary}
                      incrementalStats={analysisResult.incremental_stats || analysisResult.call_graph_summary?.incremental}
                    />
                  </div>
                  {analysisResult.health && (
                    <div className="animate-fade-in-up delay-2">
                      <HealthCard health={analysisResult.health} />
                    </div>
                  )}
                  <div className="animate-fade-in-up delay-3">
                    <DeductionsTable deductions={allDeductions} onSelectRule={handleOpenRule} />
                  </div>
                </div>
              )}

              {activeTab === 'findings' && (
                <div className="animate-fade-in-up">
                  <ErrorBoundary fallbackTitle="Findings Explorer Error">
                    <FindingsExplorer
                      findings={analysisResult.findings}
                      repositoryId={selectedRepo?.id}
                      analysisId={analysisResult.id}
                    />
                  </ErrorBoundary>
                </div>
              )}

              {activeTab === 'graph' && (
                <div className="animate-fade-in-up">
                  <ArchitectureGraph graph={analysisResult.component_graph} />
                </div>
              )}

              {activeTab === 'diff' && (
                <div className="animate-fade-in-up">
                  <DifferentialView currentResult={analysisResult} />
                </div>
              )}
            </>
          )}

          {/* Longitudinal Trends & Velocity Tab */}
          {!loading && activeTab === 'trends' && (
            <div className="animate-fade-in-up">
              <TrendsView
                repository={selectedRepo}
                onSelectRepo={(r) => {
                  setSelectedRepo(r);
                  setRepoPath(r.path);
                }}
              />
            </div>
          )}

          {/* Policy Studio Tab */}
          {!loading && activeTab === 'policies' && (
            <div className="animate-fade-in-up">
              <PolicyStudio />
            </div>
          )}

          {/* Architecture Refactoring Hub Tab */}
          {!loading && activeTab === 'refactoring' && (
            <div className="animate-fade-in-up">
              <RefactoringHub
                repositoryId={selectedRepo?.id}
                analysisId={analysisResult?.id}
              />
            </div>
          )}

          {/* No Result Empty State */}
          {!loading && !analysisResult && !error && activeTab !== 'trends' && activeTab !== 'policies' && activeTab !== 'refactoring' && (
            <div className="panel p-16 text-center space-y-4 animate-fade-in-up">
              <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mx-auto flex items-center justify-center">
                <FolderSearch className="w-8 h-8" />
              </div>
              <div className="space-y-1.5 max-w-md mx-auto">
                <h3 className="text-base font-bold text-white tracking-tight">Ready for Codebase Audit</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Enter a repository directory path above and click <strong className="text-cyan-400">Analyze</strong> to
                  inspect vulnerabilities, component layering, and deterministic codebase health.
                </p>
              </div>
            </div>
          )}
        </main>

        {/* Console Footer */}
        <footer className="border-t border-slate-800/50 bg-[#080C14]/80 backdrop-blur py-3 text-xs text-slate-500 font-mono">
          <div className="max-w-[1400px] mx-auto px-6 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/70"></span>
              <span className="text-slate-400">CodeSentinel</span>
              <span className="text-slate-700">•</span>
              <span>Security & Architecture Console</span>
            </div>
            <p className="text-[10px] text-slate-600">Deterministic Static AST & Taint Engine</p>
          </div>
        </footer>
      </div>

      {/* Rule Catalog Modal */}
      <RuleCatalogModal
        isOpen={rulesModalOpen}
        onClose={() => setRulesModalOpen(false)}
        selectedRuleId={selectedRuleId}
      />

      {/* Analysis History Modal (Phase 10) */}
      <AnalysisHistoryModal
        isOpen={historyModalOpen}
        onClose={() => setHistoryModalOpen(false)}
        repository={selectedRepo}
        onSelectRepo={(r) => {
          setSelectedRepo(r);
          setRepoPath(r.path);
        }}
        onSelectSnapshot={(result, summary) => {
          setAnalysisResult(result);
          setActiveSnapshotMeta(summary);
        }}
        currentLoadedSnapshotId={activeSnapshotMeta?.id}
      />
    </div>
  );
};

export default App;
