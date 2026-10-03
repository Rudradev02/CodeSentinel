import React, { useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileCode,
  Send,
  Lock,
  UserCheck,
  Lightbulb,
} from 'lucide-react';
import { approveSecurityPolicy, authorSecurityPolicy } from '../../api/client';
import { PolicyAuthorResponseDTO } from '../../types';

const POLICY_TEMPLATES = [
  {
    title: 'SQL Query Parameterization',
    prompt: 'All SQL database queries originating from HTTP request parameters must use parameterized queries or integer casting.',
  },
  {
    title: 'Command Execution Defense',
    prompt: 'Disallow unauthenticated shell execution and require shell escaping on all CLI/process sinks.',
  },
  {
    title: 'DOM XSS Sanitization',
    prompt: 'Require DOMPurify.sanitize or HTML escaping before rendering untrusted inputs into DOM injection sinks.',
  },
  {
    title: 'Path Traversal Guard',
    prompt: 'Require path canonicalization and verification on all file system write operations from HTTP parameters.',
  },
];

export const PolicyStudio: React.FC = () => {
  const [prompt, setPrompt] = useState('');
  const [authorId, setAuthorId] = useState('policy-author@codesentinel.local');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PolicyAuthorResponseDTO | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Approval Modal State
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [approverId, setApproverId] = useState('ciso@codesentinel.local');
  const [approving, setApproving] = useState(false);
  const [approvalSuccess, setApprovalSuccess] = useState<string | null>(null);

  const handleAuthorPolicy = async (customPrompt?: string) => {
    const textToUse = customPrompt !== undefined ? customPrompt : prompt;
    if (!textToUse.trim()) return;

    setLoading(true);
    setError(null);
    setApprovalSuccess(null);

    try {
      const res = await authorSecurityPolicy(textToUse.trim(), authorId);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to author policy from natural language.');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!result?.policy_id || !approverId.trim()) return;

    setApproving(true);
    setError(null);

    try {
      const res = await approveSecurityPolicy(result.policy_id, approverId.trim());
      setApprovalSuccess(`Policy ${res.policy_id} approved by ${res.approved_by} and activated into Rule Engine.`);
      setApprovalModalOpen(false);
      if (result) {
        setResult({
          ...result,
          validation_status: 'APPROVED_ACTIVE',
        });
      }
    } catch (err: any) {
      setError(err.message || 'Approval failed.');
    } finally {
      setApproving(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2.5">
            <Sparkles className="w-6 h-6 text-emerald-400" />
            <span>Natural-Language Security Policy Studio</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Author declarative security invariants in natural language. Deterministically validated and compiled into CodeSentinel rule packs.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <span className="text-slate-400">Author:</span>
          <input
            type="text"
            value={authorId}
            onChange={(e) => setAuthorId(e.target.value)}
            className="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {/* Suggested Templates */}
      <div className="space-y-2">
        <span className="text-xs font-semibold text-slate-400 flex items-center space-x-1.5">
          <Lightbulb className="w-4 h-4 text-amber-400" />
          <span>Quick Policy Templates:</span>
        </span>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {POLICY_TEMPLATES.map((tmpl, idx) => (
            <button
              key={idx}
              onClick={() => {
                setPrompt(tmpl.prompt);
                handleAuthorPolicy(tmpl.prompt);
              }}
              className="text-left p-3 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/50 hover:bg-slate-900 transition-all group"
            >
              <span className="text-xs font-bold text-slate-200 group-hover:text-emerald-300 block mb-1">
                {tmpl.title}
              </span>
              <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                {tmpl.prompt}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Side-by-Side Authoring Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Natural Language Input */}
        <div className="panel p-5 flex flex-col space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <span>Natural Language Prompt</span>
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              {prompt.length} characters (~{Math.max(1, Math.round(prompt.length / 4))} tokens)
            </span>
          </div>

          <textarea
            rows={8}
            placeholder="Describe your security invariant (e.g. 'All SQL database queries in API routes must use parameterization and require authentication...')"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            className="w-full flex-1 p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs font-mono leading-relaxed focus:outline-none focus:border-emerald-500 transition-colors resize-none"
          />

          <div className="flex justify-between items-center pt-2">
            <span className="text-[11px] text-slate-500">
              Strict Grammar: Maps directly to SinkCategory & SecurityProperty
            </span>
            <button
              disabled={loading || !prompt.trim()}
              onClick={() => handleAuthorPolicy()}
              className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg shadow-lg disabled:opacity-50 transition-colors"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Compiling...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Translate & Validate</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right: Compiled Candidate JSON & Validation Diagnostics */}
        <div className="panel-elevated p-5 flex flex-col space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>Compiled SecurityPolicy Candidate</span>
            </span>

            {result && (
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                  result.validation_status === 'VALIDATED_CANDIDATE' || result.validation_status === 'APPROVED_ACTIVE'
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                    : 'bg-rose-950/80 text-rose-300 border-rose-800'
                }`}
              >
                {result.validation_status}
              </span>
            )}
          </div>

          {/* Validation Diagnostics Banner */}
          {result && (
            <div
              className={`p-3 rounded-lg border text-xs space-y-1 ${
                result.validation_status === 'VALIDATED_CANDIDATE' || result.validation_status === 'APPROVED_ACTIVE'
                  ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
              }`}
            >
              <div className="flex items-center space-x-1.5 font-bold">
                {result.validation_status === 'VALIDATED_CANDIDATE' || result.validation_status === 'APPROVED_ACTIVE' ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Deterministic Validation Passed</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-rose-400" />
                    <span>Validation Rejection / Ambiguity Detected</span>
                  </>
                )}
              </div>
              <ul className="list-disc list-inside space-y-0.5 text-[11px] opacity-90">
                {result.diagnostics.map((diag, idx) => (
                  <li key={idx}>{diag}</li>
                ))}
              </ul>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 text-xs text-rose-300 flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {approvalSuccess && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/80 text-xs text-emerald-300 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span>{approvalSuccess}</span>
            </div>
          )}

          {/* Candidate JSON Viewer */}
          <div className="flex-1 bg-slate-950 border border-slate-800/80 rounded-lg p-3 overflow-y-auto max-h-72">
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
              {result?.candidate_policy
                ? JSON.stringify(result.candidate_policy, null, 2)
                : '// Click "Translate & Validate" to generate a compiled candidate policy schema.'}
            </pre>
          </div>

          {/* Human Approval Action Gate */}
          {result?.validation_status === 'VALIDATED_CANDIDATE' && (
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[11px] text-amber-400 flex items-center space-x-1">
                <Lock className="w-3.5 h-3.5" />
                <span>Mandatory Human Review Gate</span>
              </span>
              <button
                onClick={() => setApprovalModalOpen(true)}
                className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow transition-colors"
              >
                <UserCheck className="w-3.5 h-3.5" />
                <span>Approve & Activate Policy</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Two-Person Approval Modal Dialog */}
      {approvalModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="panel-elevated max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100">
                Auditor Sign-off & Policy Activation
              </h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Activating policy <span className="font-mono text-cyan-300 font-bold">{result?.policy_id}</span> will register it in the authoritative <span className="font-semibold text-slate-200">SecurityPolicyRegistry</span> for all future scans.
            </p>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-400">
                Approver Identity (Auditor / Security Admin):
              </label>
              <input
                type="text"
                value={approverId}
                onChange={(e) => setApproverId(e.target.value)}
                className="w-full text-xs px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setApprovalModalOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                disabled={approving || !approverId.trim()}
                onClick={handleApprove}
                className="px-4 py-1.5 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow disabled:opacity-50"
              >
                {approving ? 'Activating...' : 'Confirm Activation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
