import React, { useEffect, useState } from 'react';
import {
  X,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCw,
  Cpu,
  Cloud,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import { enrichFinding, getFindingEnrichment } from '../../api/client';
import { AIEnrichmentDTO, FindingDTO } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { DiffPatchViewer } from './DiffPatchViewer';

interface FindingDetailDrawerProps {
  finding: FindingDTO | null;
  repositoryId?: string | null;
  analysisId?: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export const FindingDetailDrawer: React.FC<FindingDetailDrawerProps> = ({
  finding,
  repositoryId,
  analysisId,
  isOpen,
  onClose,
}) => {
  const [enrichment, setEnrichment] = useState<AIEnrichmentDTO | null>(null);
  const [loading, setLoading] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<'openrouter' | 'ollama'>('openrouter');

  // Load existing enrichment if available
  useEffect(() => {
    if (!isOpen || !finding || !repositoryId || !analysisId) {
      setEnrichment(null);
      setError(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    getFindingEnrichment(repositoryId, analysisId, finding.id)
      .then((data) => {
        if (isMounted) setEnrichment(data);
      })
      .catch((err) => {
        // 404 simply means no enrichment has been requested yet
        if (err.status !== 404 && isMounted) {
          setError(err.message || 'Failed to check enrichment status');
        }
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, finding, repositoryId, analysisId]);

  if (!isOpen || !finding) return null;

  const handleTriggerEnrichment = async (forceRefresh: boolean = false) => {
    if (!repositoryId || !analysisId) {
      setError('Active repository and snapshot are required for AI enrichment.');
      return;
    }

    setEnriching(true);
    setError(null);

    try {
      await enrichFinding(repositoryId, analysisId, finding.id, {
        provider: selectedProvider,
        force_refresh: forceRefresh,
      });

      // Poll for completion (up to 20 attempts, 1.5s interval)
      let attempts = 0;
      const pollInterval = setInterval(async () => {
        attempts++;
        try {
          const res = await getFindingEnrichment(repositoryId, analysisId, finding.id);
          if (res.status === 'COMPLETED' || res.status === 'FAILED' || res.status === 'DISABLED') {
            setEnrichment(res);
            setEnriching(false);
            clearInterval(pollInterval);
          } else if (attempts >= 20) {
            setEnriching(false);
            clearInterval(pollInterval);
            setError('AI enrichment is taking longer than expected. Please check back shortly.');
          }
        } catch {
          if (attempts >= 20) {
            setEnriching(false);
            clearInterval(pollInterval);
          }
        }
      }, 1500);
    } catch (err: any) {
      setEnriching(false);
      setError(err.message || 'Failed to trigger AI enrichment');
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-2xl bg-[#0D121D] border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-y-auto">
        {/* Drawer Header */}
        <div className="p-4 bg-[#121824] border-b border-slate-800 flex items-center justify-between sticky top-0 z-10">
          <div className="flex items-center space-x-2.5 min-w-0">
            <Sparkles className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <span>AI Triage & Remediation</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {finding.rule_id}
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono truncate max-w-md">
                {finding.location.file_path}:{finding.location.line_start}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <SeverityBadge severity={finding.severity} />
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-6 flex-1">
          {/* Finding Summary Headline */}
          <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-start space-x-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-xs font-bold text-slate-100">{finding.message || finding.rule_name}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{finding.description}</p>
              </div>
            </div>
          </div>

          {/* AI Trigger Control Bar */}
          <div className="bg-[#151D2C] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <span className="text-xs text-slate-400 font-medium">Provider:</span>
              <div className="flex items-center bg-[#0B0F17] rounded-lg p-0.5 border border-slate-700/80">
                <button
                  onClick={() => setSelectedProvider('openrouter')}
                  className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs transition-colors ${
                    selectedProvider === 'openrouter'
                      ? 'bg-emerald-500/20 text-emerald-300 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Cloud className="w-3.5 h-3.5" />
                  <span>OpenRouter</span>
                </button>
                <button
                  onClick={() => setSelectedProvider('ollama')}
                  className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs transition-colors ${
                    selectedProvider === 'ollama'
                      ? 'bg-emerald-500/20 text-emerald-300 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Ollama (Local)</span>
                </button>
              </div>
            </div>

            <button
              onClick={() => handleTriggerEnrichment(!!enrichment)}
              disabled={enriching || loading}
              className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-lg transition-all ${
                enriching || loading
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950/40'
              }`}
            >
              {enriching ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Triage in Progress...</span>
                </>
              ) : enrichment ? (
                <>
                  <RotateCw className="w-3.5 h-3.5" />
                  <span>Re-run AI Triage</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Run AI Triage</span>
                </>
              )}
            </button>
          </div>

          {/* Error Message Banner */}
          {error && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-start space-x-2 text-xs text-rose-300">
              <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* AI Enrichment Results Card */}
          {enrichment && enrichment.status === 'COMPLETED' && (
            <div className="space-y-4">
              {/* Triage Verdict & Confidence */}
              <div className="bg-[#121824] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    {enrichment.is_likely_true_positive ? (
                      <span className="flex items-center space-x-1.5 text-xs font-bold px-2.5 py-1 rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/30">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                        <span>True Positive Assessment</span>
                      </span>
                    ) : (
                      <span className="flex items-center space-x-1.5 text-xs font-bold px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Likely False Positive / Mitigated</span>
                      </span>
                    )}

                    <span className="text-[11px] text-slate-500 font-mono">
                      via {enrichment.provider} ({enrichment.model})
                    </span>
                  </div>

                  {enrichment.confidence_score !== null && enrichment.confidence_score !== undefined && (
                    <div className="flex items-center space-x-1.5 text-xs font-semibold text-slate-300">
                      <span>Confidence:</span>
                      <span className="text-emerald-400 font-mono">
                        {Math.round(enrichment.confidence_score * 100)}%
                      </span>
                    </div>
                  )}
                </div>

                {/* Risk Summary */}
                {enrichment.risk_summary && (
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                      Contextual Risk Summary:
                    </span>
                    <p className="text-xs text-slate-200 leading-relaxed font-medium">
                      {enrichment.risk_summary}
                    </p>
                  </div>
                )}

                {/* Technical Reasoning */}
                {enrichment.technical_reasoning && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                      Technical Reasoning & Analysis:
                    </span>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {enrichment.technical_reasoning}
                    </p>
                  </div>
                )}

                {/* Assumptions & Limitations */}
                {enrichment.assumptions_limitations && enrichment.assumptions_limitations.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1 mb-1.5">
                      <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
                      <span>Contextual Assumptions:</span>
                    </span>
                    <ul className="list-disc list-inside space-y-1 text-xs text-slate-400">
                      {enrichment.assumptions_limitations.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Proposed Remediation Diff */}
              {enrichment.proposed_patch ? (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-200 flex items-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Proposed Unified Diff Patch</span>
                  </h4>
                  <DiffPatchViewer
                    patch={enrichment.proposed_patch}
                    language={finding.evidence.language}
                  />
                </div>
              ) : (
                enrichment.prescribed_remediation && (
                  <div className="p-4 bg-[#121824] border border-slate-800 rounded-xl space-y-1">
                    <span className="text-xs font-bold text-emerald-300 flex items-center space-x-1.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>Prescribed Guidance</span>
                    </span>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {enrichment.prescribed_remediation}
                    </p>
                  </div>
                )
              )}
            </div>
          )}

          {/* Empty State / Not Enriched Yet */}
          {!enrichment && !enriching && !loading && (
            <div className="bg-[#121824]/50 border border-dashed border-slate-800 rounded-xl p-8 text-center space-y-3">
              <Sparkles className="w-8 h-8 text-slate-600 mx-auto" />
              <div>
                <h4 className="text-xs font-bold text-slate-300">No AI Triage Record Yet</h4>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                  Click "Run AI Triage" above to perform bounded AST scope extraction, secret scrubbing, and LLM triage with proposed unified diffs.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
