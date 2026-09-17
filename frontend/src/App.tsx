import React, { useEffect, useState } from 'react';
import { 
  Shield, 
  Activity, 
  Server, 
  Cpu, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  Layers, 
  FileCode2,
  Terminal
} from 'lucide-react';
import { fetchHealth } from './services/api';
import { HealthResponse } from './types';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const loadHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchHealth();
      setHealth(data);
      setLastChecked(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect to backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealth();
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col selection:bg-emerald-500/30">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-[#121824]/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                CodeSentinel
              </span>
              <span className="ml-2.5 text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Phase 1: Foundation
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={loadHealth}
              disabled={loading}
              className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700/60 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
              <span>Refresh Status</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {/* Foundation Hero Banner */}
        <section className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-b from-[#161F30]/70 to-[#101622]/90 p-8 shadow-2xl">
          <div className="relative z-10 max-w-3xl space-y-4">
            <h1 className="text-3xl font-extrabold tracking-tight text-white">
              AI-Assisted Codebase Architecture & Security Auditor
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed">
              CodeSentinel establishes an evidence-first static analysis foundation. The core analyzer engine 
              operates independently from the web layer using deterministic AST parsing and graph modeling. 
              LLM capabilities are reserved strictly for contextual validation, explanation, and remediation suggestions.
            </p>
          </div>
          <div className="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-emerald-500/5 to-transparent pointer-events-none" />
        </section>

        {/* Backend Live Health Grid */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-200 flex items-center space-x-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              <span>Backend & Engine Readiness</span>
            </h2>
            {lastChecked && (
              <span className="text-xs text-slate-500">
                Last checked: {lastChecked.toLocaleTimeString()}
              </span>
            )}
          </div>

          {error ? (
            <div className="p-5 rounded-xl border border-rose-500/30 bg-rose-500/10 flex items-start space-x-3 text-rose-300">
              <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="font-semibold">Backend Communication Offline</p>
                <p className="text-rose-300/80 mt-1">{error}</p>
                <p className="text-xs text-slate-400 mt-2">
                  Verify the backend server is running on <code className="text-slate-300 bg-slate-800 px-1.5 py-0.5 rounded">http://localhost:8000</code>.
                </p>
              </div>
            </div>
          ) : health ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Service Status */}
              <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/80 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>API Status</span>
                  <Server className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="mt-3">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-xl font-bold text-white capitalize">{health.status}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">{health.service} v{health.version}</p>
                </div>
              </div>

              {/* Uptime */}
              <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/80 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Server Uptime</span>
                  <Activity className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="mt-3">
                  <span className="text-xl font-bold text-white">{health.uptime_seconds.toFixed(1)}s</span>
                  <p className="text-xs text-slate-500 mt-1">Environment: {health.environment}</p>
                </div>
              </div>

              {/* Analyzer Engine */}
              <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/80 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Analyzer Engine</span>
                  <Cpu className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="mt-3">
                  <div className="flex items-center space-x-1.5 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>{health.components.analyzer_engine}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">Decoupled standalone package</p>
                </div>
              </div>

              {/* Persistence State */}
              <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/80 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Database & Queue</span>
                  <Layers className="w-4 h-4 text-amber-400" />
                </div>
                <div className="mt-3">
                  <span className="text-sm font-semibold text-amber-400/90">Phase 4 Target</span>
                  <p className="text-xs text-slate-500 mt-1">PostgreSQL & Redis placeholders</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl border border-slate-800 bg-[#121824]/50 flex items-center justify-center text-slate-400 text-sm">
              <RefreshCw className="w-4 h-4 animate-spin mr-2 text-emerald-400" />
              <span>Connecting to CodeSentinel backend...</span>
            </div>
          )}
        </section>

        {/* Phase 1 Architectural Principles (Truthful, No Fake Data) */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-slate-200 flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            <span>Core Design Invariants</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Deterministic */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/70 space-y-2">
              <div className="text-xs font-semibold text-emerald-400 tracking-wider uppercase">
                Deterministic Analysis
              </div>
              <h3 className="font-semibold text-white text-base">AST & Syntax Verification</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Rules detect syntax-grounded violations with explicit AST evidence. Zero hallucinated vulnerabilities 
                or unanchored alerts.
              </p>
            </div>

            {/* Heuristic */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/70 space-y-2">
              <div className="text-xs font-semibold text-amber-400 tracking-wider uppercase">
                Heuristic Analysis
              </div>
              <h3 className="font-semibold text-white text-base">Structural Patterns</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Evaluates dependency cycles, high module fan-out, and semantic patterns where risk confidence depends on 
                surrounding evidence.
              </p>
            </div>

            {/* AI-Assisted */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#121824]/70 space-y-2">
              <div className="text-xs font-semibold text-blue-400 tracking-wider uppercase">
                AI-Assisted Assessment
              </div>
              <h3 className="font-semibold text-white text-base">Bounded LLM Remediation</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                LLMs operate exclusively on bounded AST snippets for candidate findings—producing plain-language explanations 
                and minimal diff patches. Never the sole vulnerability detector.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0E131C] py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileCode2 className="w-4 h-4 text-slate-400" />
            <span>CodeSentinel &copy; 2026. Phase 1 Architecture Foundation.</span>
          </div>
          <span>FastAPI &bull; React 18 &bull; Vite &bull; Tailwind &bull; Standalone Analyzer</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
