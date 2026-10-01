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
  Flame,
  Activity,
  ThumbsUp,
  ThumbsDown,
  Shield,
} from 'lucide-react';
import { enrichFinding, getFindingEnrichment, getFindingPriority, submitTriageFeedback } from '../../api/client';
import { AIEnrichmentDTO, FindingDTO, PrioritizationDTO } from '../../types';
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
  const [priority, setPriority] = useState<PrioritizationDTO | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);
  const [showFpDialog, setShowFpDialog] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [loading, setLoading] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<'openrouter' | 'ollama'>('openrouter');

  // Load existing enrichment and prioritization if available
  useEffect(() => {
    if (!isOpen || !finding || !repositoryId || !analysisId) {
      setEnrichment(null);
      setPriority(null);
      setError(null);
      setFeedbackSuccess(null);
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
        if (err.status !== 404 && isMounted) {
          setError(err.message || 'Failed to check enrichment status');
        }
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    getFindingPriority(repositoryId, analysisId, finding.id)
      .then((data) => {
        if (isMounted) setPriority(data);
      })
      .catch(() => {});

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
        finding_data: finding,
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

  const handleFeedback = async (label: string, reason: string = '') => {
    if (!repositoryId || !analysisId) return;
    setSubmittingFeedback(true);
    try {
      await submitTriageFeedback(repositoryId, analysisId, finding.id, {
        label,
        reason,
        reviewer_id: 'security-analyst@codesentinel.local',
      });
      setFeedbackSuccess(`Recorded triage feedback: ${label.replace('_', ' ')}`);
      setShowFpDialog(false);
      setFpReason('');
    } catch (err: any) {
      setError(err.message || 'Failed to submit triage feedback');
    } finally {
      setSubmittingFeedback(false);
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
            {priority && (
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono border ${
                  priority.priority_band === 'P0_IMMEDIATE'
                    ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                    : priority.priority_band === 'P1_HIGH'
                    ? 'bg-orange-950/80 text-orange-300 border-orange-800'
                    : priority.priority_band === 'P2_MEDIUM'
                    ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                    : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}
              >
                {priority.priority_band.replace('_', ' ')} ({priority.priority_score})
              </span>
            )}
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

          {/* Phase 30: Exploitability Matrix & Priority Breakdown */}
          {priority && (
            <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Flame className="w-4 h-4 text-rose-400" />
                  <span className="text-xs font-bold text-slate-100 uppercase tracking-wide">
                    Exploitability Matrix & Priority
                  </span>
                </div>
                <span className="text-xs font-mono text-emerald-400 font-semibold">
                  Score: {priority.priority_score} / 100
                </span>
              </div>

              {/* Exploitability progress bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-[11px] text-slate-400">
                  <span>Technical Exploitability</span>
                  <span className="font-mono">{Math.round(priority.exploitability_score * 100)}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500 rounded-full"
                    style={{ width: `${Math.min(100, Math.max(5, priority.exploitability_score * 100))}%` }}
                  />
                </div>
              </div>

              {/* Factor breakdown grid */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(priority.contributing_factors || {}).map(([name, factor]) => (
                  <div key={name} className="p-2 rounded bg-slate-900/60 border border-slate-800/80 space-y-1">
                    <div className="flex justify-between text-[10px] text-slate-400 uppercase font-semibold">
                      <span>{name.replace('_', ' ')}</span>
                      <span className="font-mono text-slate-200">{(factor.score * 100).toFixed(0)}%</span>
                    </div>
                    <p className="text-[11px] text-slate-300 truncate" title={factor.evidence}>
                      {factor.evidence}
                    </p>
                  </div>
                ))}
              </div>

              {priority.rationale && (
                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs text-slate-300">
                  <span className="font-semibold text-slate-400 mr-1.5">Grounded Rationale:</span>
                  {priority.rationale}
                </div>
              )}
            </div>
          )}

          {/* Phase 30: ML False-Positive Triage Feedback Widget */}
          <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-100 uppercase tracking-wide">
                  ML Triage Feedback
                </span>
              </div>
              <span className="text-[11px] font-mono text-cyan-300">
                Advisory Human Gate
              </span>
            </div>

            {feedbackSuccess && (
              <div className="p-2.5 rounded bg-emerald-950/60 border border-emerald-800/80 text-xs text-emerald-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>{feedbackSuccess}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <button
                disabled={submittingFeedback}
                onClick={() => handleFeedback('TRUE_POSITIVE')}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
              >
                <ThumbsUp className="w-3.5 h-3.5 text-emerald-400" />
                <span>Confirm True Positive</span>
              </button>
              <button
                disabled={submittingFeedback}
                onClick={() => setShowFpDialog(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/40 hover:bg-rose-950/70 text-rose-300 border border-rose-800/80 transition-colors"
              >
                <ThumbsDown className="w-3.5 h-3.5 text-rose-400" />
                <span>Mark False Positive</span>
              </button>
              <button
                disabled={submittingFeedback}
                onClick={() => handleFeedback('ACCEPTED_RISK')}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-950/40 hover:bg-amber-950/70 text-amber-300 border border-amber-800/80 transition-colors"
              >
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span>Accept Risk</span>
              </button>
            </div>

            {showFpDialog && (
              <div className="p-3 bg-slate-900 border border-slate-700 rounded-lg space-y-2 mt-2">
                <span className="text-xs font-semibold text-slate-300 block">
                  False Positive Justification:
                </span>
                <input
                  type="text"
                  placeholder="e.g. Mock test fixture, constant input, validated upstream..."
                  value={fpReason}
                  onChange={(e) => setFpReason(e.target.value)}
                  className="w-full text-xs px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                />
                <div className="flex justify-end space-x-2 pt-1">
                  <button
                    onClick={() => setShowFpDialog(false)}
                    className="px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                  <button
                    disabled={submittingFeedback || !fpReason.trim()}
                    onClick={() => handleFeedback('FALSE_POSITIVE', fpReason)}
                    className="px-3 py-1 text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white rounded disabled:opacity-50"
                  >
                    Submit Feedback
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Phase 24: Policy Verification & Proof Obligations */}
          {Boolean(
            (finding.dataflow_evidence as any)?.proof_obligations?.length ||
              (finding.dataflow_evidence as any)?.policy_evaluation
          ) && (
            <div className="bg-[#121824]/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-bold text-slate-100 uppercase tracking-wide">
                    Policy Proof Obligations
                  </span>
                </div>
                {(finding.dataflow_evidence as any)?.policy_evaluation && (
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                      (finding.dataflow_evidence as any).policy_evaluation.evaluation_result === 'PROVEN_SAFE'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {(finding.dataflow_evidence as any).policy_evaluation.policy_id} :{' '}
                    {(finding.dataflow_evidence as any).policy_evaluation.evaluation_result}
                  </span>
                )}
              </div>

              {/* Proof Obligations List */}
              {(finding.dataflow_evidence as any)?.proof_obligations && (
                <div className="space-y-2">
                  {(finding.dataflow_evidence as any).proof_obligations.map((obl: any, idx: number) => {
                    const isSafe = obl.state === 'PROVEN_SAFE';
                    const isViolated = obl.state === 'PROVEN_VIOLATION';
                    return (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-lg border text-xs space-y-1 ${
                          isSafe
                            ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                            : isViolated
                            ? 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                            : 'bg-slate-900/60 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-semibold text-[11px]">{obl.kind}</span>
                          <span
                            className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                              isSafe
                                ? 'text-emerald-400 bg-emerald-900/40'
                                : isViolated
                                ? 'text-rose-400 bg-rose-900/40'
                                : 'text-amber-400 bg-amber-900/40'
                            }`}
                          >
                            {obl.state}
                          </span>
                        </div>
                        <p className="text-[11px] opacity-90">{obl.evidence_details}</p>
                        {obl.unknown_reason && (
                          <p className="text-[10px] text-amber-400/90 italic">
                            Indeterminate: {obl.unknown_reason}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

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
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-start justify-between space-x-2 text-xs text-rose-300">
              <div className="flex items-start space-x-2">
                <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
              <button
                onClick={() => setError(null)}
                className="text-rose-400 hover:text-rose-200 text-xs px-1.5 py-0.5 rounded transition"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Enriching in-progress state */}
          {enriching && (
            <div className="bg-[#121824] border border-emerald-500/30 rounded-xl p-6 text-center space-y-3 animate-pulse shadow-lg shadow-emerald-950/20">
              <Sparkles className="w-7 h-7 text-emerald-400 animate-spin mx-auto" />
              <div>
                <h4 className="text-xs font-bold text-slate-200">Analyzing Context & Synthesizing Remediation...</h4>
                <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                  Extracting bounded AST context, scrubbing secrets, and evaluating finding with {selectedProvider === 'ollama' ? 'Ollama (Local)' : 'OpenRouter'}.
                </p>
              </div>
            </div>
          )}

          {/* Failed enrichment state */}
          {enrichment && enrichment.status === 'FAILED' && !enriching && (
            <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4 space-y-2 text-xs text-rose-300">
              <div className="flex items-center space-x-2 font-bold">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>AI Triage Notice</span>
              </div>
              <p className="text-slate-300">{enrichment.error_message || 'Could not complete AI analysis.'}</p>
              <button
                onClick={() => handleTriggerEnrichment(true)}
                className="mt-2 px-3 py-1 bg-rose-600/30 hover:bg-rose-600/50 text-rose-200 rounded text-xs transition"
              >
                Retry AI Triage
              </button>
            </div>
          )}

          {/* Disabled enrichment state */}
          {enrichment && enrichment.status === 'DISABLED' && !enriching && (
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 space-y-2 text-xs text-amber-300">
              <div className="flex items-center space-x-2 font-bold">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>AI Triage Disabled</span>
              </div>
              <p className="text-slate-300">{enrichment.error_message || 'AI enrichment is disabled in configuration.'}</p>
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
