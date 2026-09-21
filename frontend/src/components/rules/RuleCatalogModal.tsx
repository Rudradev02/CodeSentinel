import React, { useEffect, useState } from 'react';
import { X, Search, BookOpen } from 'lucide-react';
import { fetchRules } from '../../api/client';
import { RuleMetadataDTO } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';

interface RuleCatalogModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedRuleId?: string | null;
}

export const RuleCatalogModal: React.FC<RuleCatalogModalProps> = ({
  isOpen,
  onClose,
  selectedRuleId,
}) => {
  const [rules, setRules] = useState<RuleMetadataDTO[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState<'ALL' | 'SECURITY' | 'ARCHITECTURE'>('ALL');
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    setError(null);
    fetchRules()
      .then((res) => {
        setRules(res.rules);
        if (selectedRuleId) {
          setExpandedRuleId(selectedRuleId);
          setSearchTerm(selectedRuleId);
        }
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load rules catalog');
      })
      .finally(() => {
        setLoading(false);
      });
  }, [isOpen, selectedRuleId]);

  if (!isOpen) return null;

  const filteredRules = rules.filter((r) => {
    const matchesCat = activeCategory === 'ALL' || r.category.toUpperCase() === activeCategory;
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      !term ||
      r.rule_id.toLowerCase().includes(term) ||
      r.name.toLowerCase().includes(term) ||
      r.description.toLowerCase().includes(term);
    return matchesCat && matchesSearch;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="bg-[#101622] border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-[#0B0F17] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Registered Static Analysis Rules
              </h2>
              <p className="text-xs text-slate-400">
                Official security and architecture rule catalog enforced by the CodeSentinel engine
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter bar */}
        <div className="p-4 border-b border-slate-800/80 bg-[#121824]/60 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by rule ID, title, or keywords..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>

          <div className="flex items-center space-x-1.5 text-xs">
            {(['ALL', 'SECURITY', 'ARCHITECTURE'] as const).map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3 py-1 rounded-full text-xs font-semibold transition-all ${
                  activeCategory === cat
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-slate-700/40'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Rule list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {loading ? (
            <div className="py-16 text-center text-xs text-slate-400">Loading rule definitions...</div>
          ) : error ? (
            <div className="py-16 text-center text-xs text-rose-400">{error}</div>
          ) : filteredRules.length === 0 ? (
            <div className="py-16 text-center text-xs text-slate-500">No rules matched your query.</div>
          ) : (
            filteredRules.map((rule) => {
              const isExpanded = expandedRuleId === rule.rule_id;
              return (
                <div
                  key={rule.rule_id}
                  className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 transition-all hover:border-slate-700"
                >
                  <div
                    className="flex items-center justify-between gap-3 cursor-pointer"
                    onClick={() => setExpandedRuleId(isExpanded ? null : rule.rule_id)}
                  >
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-xs font-bold text-emerald-400">{rule.rule_id}</span>
                      <SeverityBadge severity={rule.severity} />
                      <span className="text-xs font-semibold text-slate-200">{rule.name}</span>
                    </div>
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                      {rule.category}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">{rule.description}</p>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-2 text-xs bg-[#0B0F17]/60 p-3 rounded-lg">
                      {rule.rationale && (
                        <div>
                          <span className="font-bold text-slate-300">Rationale: </span>
                          <span className="text-slate-400">{rule.rationale}</span>
                        </div>
                      )}
                      <div>
                        <span className="font-bold text-emerald-300">Remediation: </span>
                        <span className="text-slate-400">{rule.remediation}</span>
                      </div>
                      <div className="flex flex-wrap gap-4 text-[11px] text-slate-500 pt-1 font-mono">
                        {rule.cwe_id && <span>CWE: {rule.cwe_id}</span>}
                        {rule.owasp_category && <span>OWASP: {rule.owasp_category}</span>}
                        <span>Confidence: {rule.confidence}</span>
                        <span>Evidence: {rule.evidence_type}</span>
                        {rule.supported_languages?.length > 0 && (
                          <span>Languages: {rule.supported_languages.join(', ')}</span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
