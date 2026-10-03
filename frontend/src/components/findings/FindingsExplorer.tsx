import React, { useMemo, useState } from 'react';
import {
  Search,
  ArrowUpDown,
  AlertOctagon,
  Sparkles,
} from 'lucide-react';
import { FindingDTO } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { MonacoViewer } from './MonacoViewer';
import { FindingDetailDrawer } from './FindingDetailDrawer';

interface FindingsExplorerProps {
  findings: FindingDTO[];
  initialSelectedId?: string;
  repositoryId?: string | null;
  analysisId?: string | null;
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const FindingsExplorer: React.FC<FindingsExplorerProps> = ({
  findings,
  initialSelectedId,
  repositoryId,
  analysisId,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'severity' | 'file' | 'rule'>('severity');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    initialSelectedId || (findings.length > 0 ? findings[0].id : null)
  );
  const [drawerFinding, setDrawerFinding] = useState<FindingDTO | null>(null);


  // Filter and sort findings deterministically
  const filteredFindings = useMemo(() => {
    let result = [...findings];

    // 1. Search term
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      result = result.filter(
        (f) =>
          f.rule_id.toLowerCase().includes(term) ||
          f.message.toLowerCase().includes(term) ||
          f.location.file_path.toLowerCase().includes(term) ||
          f.description.toLowerCase().includes(term)
      );
    }

    // 2. Category filter
    if (selectedCategory !== 'ALL') {
      result = result.filter((f) => f.category.toUpperCase() === selectedCategory);
    }

    // 3. Severity filter
    if (selectedSeverity !== 'ALL') {
      result = result.filter((f) => f.severity.toUpperCase() === selectedSeverity);
    }

    // 4. Sort
    result.sort((a, b) => {
      if (sortBy === 'severity') {
        const diff = (SEVERITY_ORDER[b.severity.toUpperCase()] || 0) - (SEVERITY_ORDER[a.severity.toUpperCase()] || 0);
        if (diff !== 0) return diff;
      } else if (sortBy === 'file') {
        const fileDiff = a.location.file_path.localeCompare(b.location.file_path);
        if (fileDiff !== 0) return fileDiff;
      } else if (sortBy === 'rule') {
        const ruleDiff = a.rule_id.localeCompare(b.rule_id);
        if (ruleDiff !== 0) return ruleDiff;
      }
      return (a.location.line_start || 0) - (b.location.line_start || 0);
    });

    return result;
  }, [findings, searchTerm, selectedCategory, selectedSeverity, sortBy]);

  // Keep selected finding up to date
  const activeFinding = useMemo(() => {
    if (!filteredFindings.length) return null;
    const found = filteredFindings.find((f: FindingDTO) => f.id === selectedFindingId);
    return found || filteredFindings[0];
  }, [filteredFindings, selectedFindingId]);

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings by rule, message, or file path..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>

          {/* Sort Switcher */}
          <div className="flex items-center space-x-2 shrink-0">
            <span className="text-xs text-slate-400 flex items-center space-x-1">
              <ArrowUpDown className="w-3.5 h-3.5" />
              <span>Sort:</span>
            </span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'severity' | 'file' | 'rule')}
              className="bg-[#0B0F17] border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value="severity">Severity Rank</option>
              <option value="file">File Path</option>
              <option value="rule">Rule ID</option>
            </select>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/60 text-xs">
          {/* Severity Pills */}
          <div className="flex items-center space-x-1.5 flex-wrap">
            <span className="text-slate-400 mr-1 text-[11px] font-semibold uppercase tracking-wider">Severity:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold transition-all ${
                  selectedSeverity === sev
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-slate-700/40'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Category Pills */}
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400 mr-1 text-[11px] font-semibold uppercase tracking-wider">Category:</span>
            {['ALL', 'SECURITY', 'ARCHITECTURE'].map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold transition-all ${
                  selectedCategory === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-slate-700/40'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Master-Detail Layout */}
      {filteredFindings.length === 0 ? (
        <div className="bg-[#0E1524]/60 border border-slate-800 rounded-xl p-12 text-center space-y-2">
          <AlertOctagon className="w-8 h-8 text-slate-500 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-200">
            {findings.length === 0
              ? 'No supported source-to-sink data-flow paths detected.'
              : 'No Findings Match Your Filters'}
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            {findings.length === 0
              ? 'Absence of reported findings does not imply the repository is completely vulnerability-free. Only supported static data-flow sources, sinks, and architectural metrics were evaluated.'
              : 'Try adjusting search terms, resetting severity, or clearing category filters.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Finding List (Master) */}
          <div className="lg:col-span-5 space-y-2 max-h-[680px] overflow-y-auto pr-1">
            {filteredFindings.map((f: FindingDTO) => {
              const isSelected = activeFinding?.id === f.id;
              const sev = f.severity?.toUpperCase();
              let stripeColor = 'bg-slate-600';
              if (sev === 'CRITICAL') stripeColor = 'bg-rose-500';
              else if (sev === 'HIGH') stripeColor = 'bg-orange-500';
              else if (sev === 'MEDIUM') stripeColor = 'bg-amber-500';
              else if (sev === 'LOW') stripeColor = 'bg-blue-500';

              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFindingId(f.id)}
                  className={`relative group p-3.5 pl-4 rounded-xl border transition-all duration-150 cursor-pointer overflow-hidden ${
                    isSelected
                      ? 'bg-[#131E33] border-emerald-500/60 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
                      : 'bg-[#0E1524]/80 border-slate-800/80 hover:bg-[#121B2C] hover:border-slate-700'
                  }`}
                >
                  {/* Left severity indicator stripe */}
                  <div className={`absolute left-0 top-0 bottom-0 w-1 ${stripeColor}`} />

                  {/* Header Row: Severity + Rule ID + Category + Confidence */}
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center space-x-1.5 flex-wrap gap-y-1">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-800/90 text-slate-300 border border-slate-700/70">
                        {f.rule_id}
                      </span>
                      {f.confidence && (
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900/60 px-1.5 py-0.5 rounded border border-slate-800">
                          Conf: <strong className="text-slate-200">{f.confidence}</strong>
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono uppercase font-bold text-slate-500 tracking-wider">
                      {f.category}
                    </span>
                  </div>

                  {/* Title */}
                  <p className="text-xs font-semibold text-slate-100 group-hover:text-white line-clamp-1 transition-colors">
                    {f.message || f.rule_name}
                  </p>

                  {/* Location & Inspect Indicator */}
                  <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span className="truncate max-w-[200px] text-slate-300">
                      {f.location.file_path}
                    </span>
                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="text-slate-500">
                        L{f.location.line_start}
                      </span>
                      {isSelected && (
                        <span className="text-[10px] text-emerald-400 font-semibold flex items-center">
                          Inspect →
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Monaco Evidence Viewer (Detail) */}
          <div className="lg:col-span-7 h-[680px] sticky top-20 flex flex-col space-y-3">
            {activeFinding ? (
              <>
                {/* AI Triage Quick Action Banner */}
                <div className="bg-gradient-to-r from-[#0E1524] via-[#12182B] to-[#17142E] border border-purple-500/30 rounded-xl p-3.5 flex items-center justify-between shadow-md shrink-0">
                  <div className="flex items-center space-x-2.5">
                    <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
                      <Sparkles className="w-4 h-4" />
                    </div>
                    <div>
                      <span className="text-xs font-bold text-white block">AI Triage & Remediation</span>
                      <span className="text-[11px] text-slate-400">AST scope extraction, taint trace validation & proposed diffs</span>
                    </div>
                  </div>

                  <button
                    onClick={() => setDrawerFinding(activeFinding)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-md shadow-purple-950/40 hover:shadow-[0_0_12px_rgba(168,85,247,0.35)] transition-all shrink-0 cursor-pointer active:scale-[0.98]"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>AI Insights & Diff</span>
                  </button>
                </div>

                <div className="flex-1 min-h-0">
                  <MonacoViewer finding={activeFinding} />
                </div>
              </>
            ) : (
              <div className="h-full flex items-center justify-center bg-[#0E1524]/40 border border-slate-800 rounded-xl text-xs text-slate-500">
                Select a finding to inspect source evidence
              </div>
            )}
          </div>
        </div>
      )}

      {/* Slide-over Finding Detail & AI Remediation Drawer */}
      <FindingDetailDrawer
        isOpen={!!drawerFinding}
        finding={drawerFinding}
        repositoryId={repositoryId}
        analysisId={analysisId}
        onClose={() => setDrawerFinding(null)}
      />
    </div>
  );
};

