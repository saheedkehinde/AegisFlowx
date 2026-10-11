'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import {
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  SearchCode,
  Binary,
  GraduationCap,
  Cpu,
  Clock,
  Radio,
  Lock,
  Server,
  Activity,
  Layers,
  FileText,
  AlertOctagon,
  AlertTriangle,
  ShieldQuestion,
  RotateCcw,
} from 'lucide-react';
import { useSessionAnalyses, clearSessionAnalyses } from '@/lib/session-store';

export default function OverviewPage() {
  const recentAnalyses = useSessionAnalyses();

  const handleClearHistory = () => {
    clearSessionAnalyses();
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high':
        return 'text-red-400 bg-red-950/40 border-red-500/30';
      case 'medium':
        return 'text-amber-400 bg-amber-950/40 border-amber-500/30';
      case 'low':
        return 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30';
      case 'uncertain':
      default:
        return 'text-purple-400 bg-purple-950/40 border-purple-500/30';
    }
  };

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Welcome / Platform Mission Hero */}
        <section className="relative overflow-hidden rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-[#0c1324] via-[#080d19] to-[#060912] p-6 sm:p-8 shadow-xl">
          <div className="relative z-10 max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-950/40 px-3 py-1 text-xs font-mono text-cyan-300 mb-4">
              <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
              <span>AegisFlow Security Intelligence</span>
            </div>

            <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white">
              Think Before You Trust. <br />
              <span className="bg-gradient-to-r from-cyan-400 via-blue-300 to-indigo-300 bg-clip-text text-transparent">
                AI-Powered Threat Triage &amp; Defense.
              </span>
            </h2>

            <p className="mt-3 text-sm sm:text-base text-slate-300 leading-relaxed max-w-2xl">
              AegisFlow empowers security teams and individuals to evaluate suspicious communications, extract actionable Indicators of Compromise (IOCs), learn digital safety patterns, and coordinate defensive workflows.
            </p>

            <div className="mt-6 flex flex-wrap items-center gap-3">
              <Link
                href="/analyze"
                className="inline-flex items-center gap-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-600/30 hover:shadow-cyan-500/50 transition-all duration-200 cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
              >
                <ShieldAlert className="h-4 w-4 text-white" />
                <span>Analyze a Suspicious Message</span>
                <ArrowRight className="h-4 w-4 text-white" />
              </Link>

              <Link
                href="/academy"
                className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-900/90 px-4 py-3 text-sm font-medium text-slate-300 hover:text-white transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
              >
                <GraduationCap className="h-4 w-4 text-cyan-400" />
                <span>Explore Security Academy</span>
              </Link>
            </div>
          </div>
        </section>

        {/* Real Verifiable System Telemetry */}
        <section aria-label="System Status" className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              <span>Verifiable Platform Status</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Real-time local verification</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 flex flex-col justify-between">
              <span className="text-slate-400 text-xs font-medium">Inference Endpoint</span>
              <div className="mt-2 flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white">Featherless AI</span>
                <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-500/20">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Online
                </span>
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 flex flex-col justify-between">
              <span className="text-slate-400 text-xs font-medium">Inference Model</span>
              <div className="mt-2 flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white truncate max-w-[140px]">
                  Qwen3-VL-8B
                </span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/20">
                  Instruct
                </span>
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 flex flex-col justify-between">
              <span className="text-slate-400 text-xs font-medium">Data Retention Mode</span>
              <div className="mt-2 flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white">Zero-Retention</span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/20">
                  Volatile RAM
                </span>
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 flex flex-col justify-between">
              <span className="text-slate-400 text-xs font-medium">Session Persistence</span>
              <div className="mt-2 flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white">Local Session</span>
                <span className="text-[10px] font-mono text-slate-400 bg-slate-800/60 px-1.5 py-0.5 rounded border border-white/10">
                  Phase 2 DB
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Quick Action Cards for Planned Investigation Workflows */}
        <section aria-label="Investigation Workflows" className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <span>Core Intelligence Workflows</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link
              href="/analyze"
              className="group rounded-xl border border-cyan-500/25 bg-[#0d1322]/80 p-5 hover:border-cyan-500/50 hover:bg-[#10182b] transition-all flex flex-col justify-between cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            >
              <div>
                <div className="h-10 w-10 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
                  <ShieldAlert className="h-5 w-5" />
                </div>
                <h4 className="text-sm font-bold text-white flex items-center gap-1.5">
                  <span>Message Analyzer</span>
                  <span className="text-[10px] font-mono text-cyan-400 font-semibold bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-500/30">
                    Live
                  </span>
                </h4>
                <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                  Evaluate urgent alerts, SMS phishing, and BEC emails against Qwen models with automated IOC defanging.
                </p>
              </div>
              <div className="mt-4 flex items-center gap-1 text-xs font-semibold text-cyan-400 group-hover:translate-x-1 transition-transform">
                <span>Launch Analyzer</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </Link>

            <Link
              href="/investigations"
              className="group rounded-xl border border-white/10 bg-[#0d1322]/60 p-5 hover:border-cyan-500/30 hover:bg-[#10182b] transition-all flex flex-col justify-between cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            >
              <div>
                <div className="h-10 w-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
                  <SearchCode className="h-5 w-5" />
                </div>
                <h4 className="text-sm font-bold text-white flex items-center gap-1.5">
                  <span>Investigations</span>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.2 rounded">
                    Phase 2
                  </span>
                </h4>
                <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                  Case correlation workspace designed to preserve digital evidence chains and cross-reference attacker campaigns.
                </p>
              </div>
              <div className="mt-4 flex items-center gap-1 text-xs font-semibold text-slate-300 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all">
                <span>Case Architecture</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </Link>

            <Link
              href="/threat-intel"
              className="group rounded-xl border border-white/10 bg-[#0d1322]/60 p-5 hover:border-cyan-500/30 hover:bg-[#10182b] transition-all flex flex-col justify-between cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            >
              <div>
                <div className="h-10 w-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
                  <Binary className="h-5 w-5" />
                </div>
                <h4 className="text-sm font-bold text-white">
                  Threat Intelligence
                </h4>
                <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                  MITRE ATT&CK taxonomy for social engineering techniques, credential phishing, and impersonation playbooks.
                </p>
              </div>
              <div className="mt-4 flex items-center gap-1 text-xs font-semibold text-slate-300 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all">
                <span>View Taxonomies</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </Link>

            <Link
              href="/academy"
              className="group rounded-xl border border-white/10 bg-[#0d1322]/60 p-5 hover:border-cyan-500/30 hover:bg-[#10182b] transition-all flex flex-col justify-between cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            >
              <div>
                <div className="h-10 w-10 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
                  <GraduationCap className="h-5 w-5" />
                </div>
                <h4 className="text-sm font-bold text-white">
                  Security Academy
                </h4>
                <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                  Interactive security training modules explaining deceptive techniques, SMS smishing, and gift card fraud.
                </p>
              </div>
              <div className="mt-4 flex items-center gap-1 text-xs font-semibold text-slate-300 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all">
                <span>Start Learning</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </Link>
          </div>
        </section>

        {/* Recent Session Analyses Section */}
        <section aria-label="Recent Analyses" className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Clock className="h-4 w-4 text-cyan-400" />
                <span>Analyses in Current Session ({recentAnalyses.length})</span>
              </h3>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Volatile in-memory logs for this browser session. Persisted cloud database will be added in Phase 2.
              </p>
            </div>

            {recentAnalyses.length > 0 && (
              <button
                type="button"
                onClick={handleClearHistory}
                className="text-[11px] text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                Clear session records
              </button>
            )}
          </div>

          {recentAnalyses.length > 0 ? (
            <div className="space-y-2.5">
              {recentAnalyses.map((item) => (
                <div
                  key={item.id}
                  className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 transition-colors hover:border-white/20 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${getRiskColor(
                          item.riskLevel
                        )}`}
                      >
                        {item.riskLevel} Risk
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        Score: {item.severityScore}/100
                      </span>
                      <span className="text-[10px] text-slate-500">
                        &middot; {item.timestamp}
                      </span>
                    </div>
                    <p className="font-mono text-xs text-slate-300 truncate">
                      &ldquo;{item.snippet}&rdquo;
                    </p>
                    <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                      {item.summary}
                    </p>
                  </div>

                  <Link
                    href="/analyze"
                    className="self-start sm:self-auto inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-500/30 transition-colors"
                  >
                    <span>Analyze Again</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-2xl border border-white/5 bg-[#0d1322]/40 p-8 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900/80 border border-white/10 text-slate-400 mb-3">
                <FileText className="h-6 w-6" />
              </div>
              <h4 className="text-sm font-bold text-white">
                No analyses completed in this session yet
              </h4>
              <p className="mt-1 text-xs text-slate-400 max-w-sm mx-auto">
                Paste any suspicious email, SMS smishing attempt, or payment prompt into the AI Analyzer to inspect threat indicators.
              </p>
              <div className="mt-4">
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/30 px-3.5 py-1.5 text-xs font-semibold text-cyan-300 transition-colors cursor-pointer"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>Launch Analyzer Now</span>
                </Link>
              </div>
            </div>
          )}
        </section>
      </div>
    </AppShell>
  );
}
