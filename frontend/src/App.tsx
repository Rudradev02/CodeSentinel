import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  FolderSearch,
} from 'lucide-react';
import { analyzeRepository, CodeSentinelAPIError } from './api/client';
import { Header } from './components/common/Header';
import { LoadingState } from './components/common/LoadingState';
import { MetricSummary } from './components/overview/MetricSummary';
import { HealthCard } from './components/overview/HealthCard';
import { DeductionsTable } from './components/overview/DeductionsTable';
import { FindingsExplorer } from './components/findings/FindingsExplorer';
import { ArchitectureGraph } from './components/architecture/ArchitectureGraph';
import { RuleCatalogModal } from './components/rules/RuleCatalogModal';
import { AnalysisResultDTO } from './types';

export const App: React.FC = () => {
  const [repoPath, setRepoPath] = useState<string>('analyzer/tests/fixtures/sample_project');
  const [analysisResult, setAnalysisResult] = useState<AnalysisResultDTO | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<{ code?: string; message: string } | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'graph'>('overview');
  const [rulesModalOpen, setRulesModalOpen] = useState<boolean>(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  const handleRunAnalysis = async (targetPath = repoPath) => {
    if (!targetPath.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const data = await analyzeRepository(targetPath);
      setAnalysisResult(data);
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
    } finally {
      setLoading(false);
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
    <div className="min-h-screen bg-[#0A0E17] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-white">
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
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6 space-y-6">
        {/* Error Banner */}
        {error && (
          <div className="bg-rose-950/70 border border-rose-800/80 rounded-xl p-4 flex items-start space-x-3.5 shadow-lg">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-rose-900/80 text-rose-200 border border-rose-700/60">
                  {error.code || 'API_ERROR'}
                </span>
                <span className="text-sm font-semibold text-white">Analysis Operation Failed</span>
              </div>
              <p className="text-xs text-rose-200/90 leading-relaxed">{error.message}</p>
            </div>
          </div>
        )}

        {/* Loading Indicator */}
        {loading && <LoadingState targetPath={repoPath} />}

        {/* Main Tabs Display */}
        {!loading && analysisResult && (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <MetricSummary summary={analysisResult.summary} />
                {analysisResult.health && <HealthCard health={analysisResult.health} />}
                <DeductionsTable deductions={allDeductions} onSelectRule={handleOpenRule} />
              </div>
            )}

            {activeTab === 'findings' && (
              <FindingsExplorer findings={analysisResult.findings} />
            )}

            {activeTab === 'graph' && (
              <ArchitectureGraph graph={analysisResult.component_graph} />
            )}
          </>
        )}

        {/* No Result Empty State */}
        {!loading && !analysisResult && !error && (
          <div className="bg-[#121824]/60 border border-slate-800 rounded-2xl p-16 text-center space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mx-auto flex items-center justify-center">
              <FolderSearch className="w-8 h-8" />
            </div>
            <div className="space-y-1 max-w-md mx-auto">
              <h3 className="text-base font-bold text-white">Ready for Codebase Audit</h3>
              <p className="text-xs text-slate-400">
                Enter a local repository directory path above and click <strong>Analyze</strong> to
                inspect vulnerabilities, component layering, and codebase health.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0B0F17] py-4 text-center text-xs text-slate-500">
        <p>CodeSentinel Phase 8 — Deterministic Static Architecture & Security Engine</p>
      </footer>

      {/* Rule Catalog Modal */}
      <RuleCatalogModal
        isOpen={rulesModalOpen}
        onClose={() => setRulesModalOpen(false)}
        selectedRuleId={selectedRuleId}
      />
    </div>
  );
};

export default App;
