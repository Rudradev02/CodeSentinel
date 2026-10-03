import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  FolderSearch,
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

  // Hook for streaming worker progress via Server-Sent Events (SSE)
  const {
    progressPercent,
    progressStage,
    progressMessage,
    cancel: cancelActiveJob,
  } = useJobProgress(activeJobId, {
    onCompleted: async (snapshotId: string) => {
      try {
        if (selectedRepo) {
          const snapshot = await getHistoricalAnalysis(selectedRepo.id, snapshotId);
          setAnalysisResult(snapshot);
          setLiveAnalysisResult(snapshot);
          setActiveSnapshotMeta(null);
        }
      } catch (err) {
        setError({
          code: 'SNAPSHOT_LOAD_FAILED',
          message: err instanceof Error ? err.message : 'Failed to load completed snapshot from storage.',
        });
      } finally {
        setLoading(false);
        setActiveJobId(null);
      }
    },
    onFailed: (errMsg: string) => {
      setError({
        code: 'ANALYSIS_FAILED',
        message: errMsg,
      });
      setLoading(false);
      setActiveJobId(null);
    },
    onCancelled: () => {
      setLoading(false);
      setActiveJobId(null);
    },
  });

  const handleRunAnalysis = async (targetPath = repoPath) => {
    if (!targetPath.trim()) return;

    setLoading(true);
    setError(null);

    try {
      let repo = selectedRepo;
      // Auto-register repository if path is not yet registered or changed
      try {
        repo = await registerRepository(targetPath.trim());
        setSelectedRepo(repo);
      } catch {
        // Fall back to existing or direct analysis if repo registration fails
      }

      if (repo) {
        try {
          // Phase 11: Async Analysis Job via Celery Worker (202 Accepted)
          const job = await runRepositoryAnalysis(repo.id);
          if (job.status === 'COMPLETED' && job.snapshot_id) {
            // Instant completion (e.g. cached snapshot)
            const snapshot = await getHistoricalAnalysis(repo.id, job.snapshot_id);
            setAnalysisResult(snapshot);
            setLiveAnalysisResult(snapshot);
            setActiveSnapshotMeta(null);
            setLoading(false);
          } else {
            // Begin SSE tracking for the active job
            setActiveJobId(job.id);
          }
        } catch (jobErr) {
          console.warn('Background worker unavailable, falling back to direct analysis:', jobErr);
          const data = await analyzeRepository(targetPath);
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
        }
      } else {
        // Fallback to legacy sync analysis
        const data = await analyzeRepository(targetPath);
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
      }
    } catch (err) {
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

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-white bg-technical-grid ambient-glow-top relative">
      {/* Header */}
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
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6 space-y-6 relative z-10">
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
            message={progressMessage || 'Running static security & architecture analysis...'}
            progressPercent={progressPercent}
            stage={progressStage}
            onCancel={activeJobId ? cancelActiveJob : undefined}
          />
        )}

        {/* Active Analysis Dashboard */}
        {!loading && analysisResult && (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-6">
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
          <div className="bg-[#0E1524]/60 border border-slate-800/80 rounded-2xl p-16 text-center space-y-4 shadow-xl animate-fade-in-up">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mx-auto flex items-center justify-center">
              <FolderSearch className="w-8 h-8" />
            </div>
            <div className="space-y-1.5 max-w-md mx-auto">
              <h3 className="text-base font-bold text-white tracking-tight">Ready for Codebase Audit</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Enter a repository directory path above and click <strong className="text-emerald-400">Analyze</strong> to
                inspect vulnerabilities, component layering, and deterministic codebase health.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Console Footer */}
      <footer className="border-t border-slate-800/80 bg-[#080C14]/90 backdrop-blur py-4 text-xs text-slate-400 font-mono">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
            <span className="font-semibold text-slate-300">CodeSentinel</span>
            <span className="text-slate-600">•</span>
            <span>Security & Architecture Console</span>
          </div>
          <p className="text-[11px] text-slate-400">Deterministic Static AST & Taint Engine</p>
        </div>
      </footer>

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
