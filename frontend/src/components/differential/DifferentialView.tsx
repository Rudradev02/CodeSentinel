import React, { useState } from 'react';
import {
  GitCompare,
  Upload,
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  Minus,
  Sparkles,
  Layers,
  Search,
  Download,
  Loader2,
  FileCode,
} from 'lucide-react';
import {
  AnalysisResultDTO,
  ComparisonResponseDTO,
  DifferentialFindingDTO,
  FindingTransition,
} from '../../types';
import { compareAnalyses, CodeSentinelAPIError } from '../../api/client';
import { MonacoViewer } from '../findings/MonacoViewer';
import { SeverityBadge } from '../common/SeverityBadge';

interface DifferentialViewProps {
  currentResult: AnalysisResultDTO | null;
}

export const DifferentialView: React.FC<DifferentialViewProps> = ({ currentResult }) => {
  const [comparison, setComparison] = useState<ComparisonResponseDTO | null>(null);
  const [baselinePath, setBaselinePath] = useState<string>('');
  const [baselineJson, setBaselineJson] = useState<Record<string, unknown> | null>(null);
  const [baselineFileName, setBaselineFileName] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [transitionFilter, setTransitionFilter] = useState<'ALL' | FindingTransition>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedFinding, setSelectedFinding] = useState<DifferentialFindingDTO | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setBaselineFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target?.result as string);
        setBaselineJson(parsed);
        setError(null);
      } catch (err) {
        setError(`Failed to parse ${file.name} as valid JSON: ${err}`);
      }
    };
    reader.readAsText(file);
  };

  const handleRunComparison = async () => {
    if (!baselineJson && !baselinePath.trim()) {
      setError('Please upload a baseline JSON report file or provide a baseline path.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await compareAnalyses({
        baseline_path: baselinePath.trim() || undefined,
        baseline_json: baselineJson || undefined,
        current_path: currentResult ? currentResult.repository_path : undefined,
      });
      setComparison(response);
      if (response.findings.length > 0) {
        setSelectedFinding(response.findings[0]);
      }
    } catch (err) {
      if (err instanceof CodeSentinelAPIError) {
        setError(`${err.code}: ${err.message}`);
      } else {
        setError(err instanceof Error ? err.message : 'Comparison failed to execute.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleExportDiff = () => {
    if (!comparison) return;
    const blob = new Blob([JSON.stringify(comparison, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentinel-diff-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered findings list
  const filteredFindings = (comparison?.findings || []).filter((df) => {
    if (transitionFilter !== 'ALL' && df.transition !== transitionFilter) {
      return false;
    }
    if (severityFilter !== 'ALL' && df.finding.severity.toUpperCase() !== severityFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchText = `${df.finding.rule_id} ${df.finding.rule_name} ${df.finding.message} ${df.finding.location.file_path}`.toLowerCase();
      if (!matchText.includes(q)) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Configuration & Input Card */}
      <div className="bg-[#101622] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Differential Baseline Comparison
              </h2>
              <p className="text-xs text-slate-400">
                Compare current codebase against a historical baseline to identify regressions and track resolved defects.
              </p>
            </div>
          </div>

          {comparison && (
            <button
              onClick={handleExportDiff}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Diff JSON</span>
            </button>
          )}
        </div>

        {/* Input selectors */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end pt-2 border-t border-slate-800/80">
          {/* File Upload Option */}
          <div className="md:col-span-6 space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center justify-between">
              <span>Baseline Report JSON File</span>
              {baselineFileName && (
                <span className="text-[10px] text-emerald-400 font-mono">Loaded: {baselineFileName}</span>
              )}
            </label>
            <div className="flex items-center space-x-2">
              <label className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-[#141B2B] hover:bg-[#1A2337] border border-dashed border-slate-700 rounded-lg cursor-pointer transition-colors text-xs text-slate-300">
                <Upload className="w-4 h-4 text-cyan-400" />
                <span>{baselineFileName ? 'Change Baseline File...' : 'Upload baseline report JSON...'}</span>
                <input
                  type="file"
                  accept=".json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          {/* Or Path Input */}
          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-medium text-slate-300">
              Or Baseline Path / Report on Server
            </label>
            <input
              type="text"
              value={baselinePath}
              onChange={(e) => setBaselinePath(e.target.value)}
              placeholder="e.g. baseline.json or /path/to/repo"
              className="w-full bg-[#141B2B] border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-all"
            />
          </div>

          {/* Run Button */}
          <div className="md:col-span-2">
            <button
              onClick={handleRunComparison}
              disabled={loading || (!baselineJson && !baselinePath.trim())}
              className="w-full inline-flex items-center justify-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-950/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Comparing...</span>
                </>
              ) : (
                <>
                  <GitCompare className="w-3.5 h-3.5" />
                  <span>Run Diff</span>
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Comparison Results Dashboard */}
      {comparison && (
        <>
          {/* Top KPI Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Health Delta */}
            <div className="bg-[#101622] border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium">Codebase Health Delta</span>
                <TrendingUp className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="my-2 flex items-baseline space-x-2">
                {comparison.health_delta ? (
                  <>
                    <span
                      className={`text-2xl font-black ${
                        comparison.health_delta.score_delta >= 0 ? 'text-emerald-400' : 'text-rose-400'
                      }`}
                    >
                      {comparison.health_delta.score_delta >= 0 ? '+' : ''}
                      {comparison.health_delta.score_delta} pts
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      ({comparison.health_delta.baseline_score} &rarr; {comparison.health_delta.current_score})
                    </span>
                  </>
                ) : (
                  <span className="text-base font-semibold text-slate-400">N/A</span>
                )}
              </div>
              {comparison.health_delta?.grade_changed && (
                <div className="text-[11px] font-semibold text-cyan-400">
                  Grade: {comparison.health_delta.baseline_grade} &rarr; {comparison.health_delta.current_grade}
                </div>
              )}
            </div>

            {/* New Regressions */}
            <div className="bg-[#101622] border border-rose-900/40 rounded-xl p-4 shadow-lg flex flex-col justify-between bg-gradient-to-br from-[#101622] to-rose-950/20">
              <div className="flex items-center justify-between text-xs text-rose-400">
                <span className="font-semibold flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-rose-400" />
                  <span>New Regressions</span>
                </span>
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-rose-900/60 border border-rose-800 text-rose-300">
                  Policy Risk
                </span>
              </div>
              <div className="my-2">
                <span className="text-3xl font-black text-rose-400">
                  {comparison.summary.new_count}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {comparison.summary.new_by_severity['CRITICAL'] || 0} Critical,{' '}
                {comparison.summary.new_by_severity['HIGH'] || 0} High
              </div>
            </div>

            {/* Resolved Findings */}
            <div className="bg-[#101622] border border-emerald-900/40 rounded-xl p-4 shadow-lg flex flex-col justify-between bg-gradient-to-br from-[#101622] to-emerald-950/20">
              <div className="flex items-center justify-between text-xs text-emerald-400">
                <span className="font-semibold flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Resolved (Fixed)</span>
                </span>
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-emerald-900/60 border border-emerald-800 text-emerald-300">
                  Remediated
                </span>
              </div>
              <div className="my-2">
                <span className="text-3xl font-black text-emerald-400">
                  {comparison.summary.resolved_count}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                Defects remediated since baseline
              </div>
            </div>

            {/* Unchanged Legacy Debt */}
            <div className="bg-[#101622] border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium">Unchanged (Legacy Debt)</span>
                <Minus className="w-4 h-4 text-slate-500" />
              </div>
              <div className="my-2">
                <span className="text-3xl font-black text-slate-200">
                  {comparison.summary.unchanged_count}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {comparison.summary.modified_count > 0
                  ? `+${comparison.summary.modified_count} modified location(s)`
                  : 'Identical baseline violations'}
              </div>
            </div>
          </div>

          {/* Component Graph Topology Delta (if available) */}
          {comparison.component_delta && (
            <div className="bg-[#101622] border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-bold text-slate-300">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Component Topology & Instability Changes</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-[#141B2B] border border-slate-800">
                  <span className="text-slate-400 text-[11px]">New Components Added:</span>
                  <p className="font-mono text-slate-200 mt-1">
                    {comparison.component_delta.new_components.length > 0
                      ? comparison.component_delta.new_components.join(', ')
                      : 'None'}
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-[#141B2B] border border-slate-800">
                  <span className="text-slate-400 text-[11px]">Components Removed:</span>
                  <p className="font-mono text-slate-200 mt-1">
                    {comparison.component_delta.removed_components.length > 0
                      ? comparison.component_delta.removed_components.join(', ')
                      : 'None'}
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-[#141B2B] border border-slate-800">
                  <span className="text-slate-400 text-[11px]">Instability (I) Deltas:</span>
                  <p className="font-mono text-slate-200 mt-1">
                    {Object.keys(comparison.component_delta.instability_deltas).length > 0
                      ? Object.entries(comparison.component_delta.instability_deltas)
                          .map(([comp, d]) => `${comp}: ${d >= 0 ? '+' : ''}${d}`)
                          .join(', ')
                      : 'Zero instability change'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Findings Differential Explorer */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left list (5 cols) */}
            <div className="lg:col-span-5 bg-[#101622] border border-slate-800 rounded-2xl p-4 space-y-4 shadow-xl">
              {/* Transition Tabs */}
              <div className="flex flex-wrap gap-1 border-b border-slate-800 pb-3">
                <button
                  onClick={() => setTransitionFilter('ALL')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    transitionFilter === 'ALL'
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All ({comparison.findings.length})
                </button>
                <button
                  onClick={() => setTransitionFilter('NEW')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    transitionFilter === 'NEW'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : 'text-rose-400/70 hover:text-rose-300'
                  }`}
                >
                  New ({comparison.summary.new_count})
                </button>
                <button
                  onClick={() => setTransitionFilter('RESOLVED')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    transitionFilter === 'RESOLVED'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-emerald-400/70 hover:text-emerald-300'
                  }`}
                >
                  Resolved ({comparison.summary.resolved_count})
                </button>
                <button
                  onClick={() => setTransitionFilter('UNCHANGED')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    transitionFilter === 'UNCHANGED'
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Unchanged ({comparison.summary.unchanged_count})
                </button>
              </div>

              {/* Search & Severity Filters */}
              <div className="flex items-center space-x-2">
                <div className="relative flex-1">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search findings by rule or path..."
                    className="w-full bg-[#141B2B] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-[#141B2B] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              {/* Findings Item List */}
              <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No findings match current filter criteria.
                  </div>
                ) : (
                  filteredFindings.map((df) => {
                    const isSelected = selectedFinding?.finding.id === df.finding.id;
                    return (
                      <div
                        key={df.finding.id}
                        onClick={() => setSelectedFinding(df)}
                        className={`p-3 rounded-xl border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-[#182133] border-cyan-500/50 shadow-md'
                            : 'bg-[#141B2B]/60 hover:bg-[#161F30] border-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1.5">
                          <div className="flex items-center space-x-1.5 min-w-0">
                            {df.transition === 'NEW' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-extrabold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">
                                NEW
                              </span>
                            )}
                            {df.transition === 'RESOLVED' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-extrabold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                RESOLVED
                              </span>
                            )}
                            {df.transition === 'MODIFIED' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-extrabold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">
                                MODIFIED
                              </span>
                            )}
                            {df.transition === 'UNCHANGED' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium uppercase bg-slate-800 text-slate-400 border border-slate-700">
                                UNCHANGED
                              </span>
                            )}
                            <span className="text-[11px] font-mono font-bold text-slate-300 truncate">
                              {df.finding.rule_id}
                            </span>
                          </div>
                          <SeverityBadge severity={df.finding.severity} />
                        </div>

                        <p className="text-xs font-semibold text-white line-clamp-1 mb-1">
                          {df.finding.message || df.finding.rule_name}
                        </p>

                        <div className="flex items-center space-x-1 text-[11px] font-mono text-slate-400">
                          <FileCode className="w-3 h-3 text-slate-500 shrink-0" />
                          <span className="truncate">{df.finding.location.file_path}</span>
                          <span>:{df.finding.location.line_start}</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right details view (7 cols) */}
            <div className="lg:col-span-7">
              {selectedFinding ? (
                <div className="space-y-4">
                  <div className="bg-[#101622] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                      <span className="text-xs font-semibold text-slate-400">Transition Details:</span>
                      <p className="text-sm font-bold text-white mt-0.5">
                        Status: <span className={selectedFinding.transition === 'NEW' ? 'text-rose-400' : selectedFinding.transition === 'RESOLVED' ? 'text-emerald-400' : 'text-slate-300'}>{selectedFinding.transition}</span>
                        {selectedFinding.match_method && (
                          <span className="ml-2 text-xs font-mono font-normal text-slate-400">
                            (Matched via {selectedFinding.match_method})
                          </span>
                        )}
                      </p>
                    </div>
                  </div>
                  <MonacoViewer finding={selectedFinding.finding} />
                </div>
              ) : (
                <div className="bg-[#101622] border border-slate-800 rounded-2xl p-16 text-center text-xs text-slate-400">
                  Select a differential finding on the left to inspect evidence in the Monaco code viewer.
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
