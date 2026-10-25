'use client';

import React, { useState, useEffect, useCallback, useMemo, useSyncExternalStore } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import ThreatBadge from '@/components/ui/ThreatBadge';
import {
  ShieldAlert,
  UploadCloud,
  Globe,
  SearchCode,
  Binary,
  GraduationCap,
  Clock,
  Activity,
  Layers,
  FileText,
  Database,
  LogIn,
  UserPlus,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  Lock,
  ExternalLink,
  ChevronRight,
  CheckCircle2,
  Sliders,
  Sparkles,
} from 'lucide-react';
import { useSessionAnalyses, clearSessionAnalyses } from '@/lib/session-store';
import { useAuth } from '@/hooks/use-auth';
import { createClient } from '@/lib/supabase/client';

interface SavedCaseSummary {
  id: string;
  input_type: string;
  input_snippet: string;
  threat_severity: 'high' | 'medium' | 'low' | 'uncertain';
  severity_score: number;
  summary: string;
  created_at: string;
}

// Reactive listener for local Security Academy progress
function subscribeAcademy(callback: () => void) {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener('aegisflow-academy-progress-updated', callback);
  window.addEventListener('storage', callback);
  return () => {
    window.removeEventListener('aegisflow-academy-progress-updated', callback);
    window.removeEventListener('storage', callback);
  };
}

function getAcademySnapshot(): string {
  if (typeof window === 'undefined') return '{}';
  try {
    return localStorage.getItem('aegisflow_academy_progress_v1') || '{}';
  } catch {
    return '{}';
  }
}

function getAcademyServerSnapshot(): string {
  return '{}';
}

function formatCaseDate(dateString?: string): string {
  if (!dateString) return 'Recent';
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return dateString;
  }
}

function formatRelativeTime(dateString?: string): string {
  if (!dateString) return 'Awaiting activity';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString;
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  } catch {
    return dateString;
  }
}

export default function OverviewPage() {
  const { user, profile, loading: authLoading } = useAuth();
  const sessionAnalyses = useSessionAnalyses();

  const [savedCases, setSavedCases] = useState<SavedCaseSummary[]>([]);
  const [savedCount, setSavedCount] = useState<number | null>(null);
  const [loadingCases, setLoadingCases] = useState(false);
  const [casesError, setCasesError] = useState<string | null>(null);

  // Subscribe to local academy verified lessons
  const academyRaw = useSyncExternalStore(
    subscribeAcademy,
    getAcademySnapshot,
    getAcademyServerSnapshot
  );

  const academyProgress = useMemo(() => {
    try {
      return JSON.parse(academyRaw);
    } catch {
      return {};
    }
  }, [academyRaw]);

  const verifiedAcademyCount = Object.values(academyProgress).filter(
    (p: any) => p?.completed
  ).length;

  // Fetch persisted cases for authenticated user
  const fetchUserCases = useCallback(async () => {
    if (!user) {
      setSavedCases([]);
      setSavedCount(0);
      return;
    }

    setLoadingCases(true);
    setCasesError(null);

    try {
      const supabase = createClient();
      const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
      if (sessionErr) throw sessionErr;

      if (!sessionData?.session) {
        setLoadingCases(false);
        return;
      }

      const { data, count, error } = await supabase
        .from('analysis_history')
        .select('id, input_type, input_snippet, threat_severity, severity_score, summary, created_at', {
          count: 'exact',
        })
        .order('created_at', { ascending: false })
        .limit(5);

      if (error) {
        setCasesError(error.message);
      } else {
        setSavedCases((data as SavedCaseSummary[]) || []);
        setSavedCount(count ?? data?.length ?? 0);
      }
    } catch (err: any) {
      setCasesError(err?.message || 'Failed to query investigation history from vault');
    } finally {
      setLoadingCases(false);
    }
  }, [user]);

  useEffect(() => {
    if (authLoading) return;
    const timer = setTimeout(() => {
      fetchUserCases();
    }, 0);
    return () => clearTimeout(timer);
  }, [authLoading, fetchUserCases]);

  const handleClearHistory = () => {
    clearSessionAnalyses();
  };

  // Derive genuine data distribution metrics from real cases
  const highRiskCount = savedCases.filter((c) => c.threat_severity === 'high').length;
  const medRiskCount = savedCases.filter((c) => c.threat_severity === 'medium').length;
  const lowRiskCount = savedCases.filter((c) => c.threat_severity === 'low' || c.threat_severity === 'uncertain').length;

  const lastActivityTimestamp = user
    ? savedCases[0]?.created_at
    : sessionAnalyses[0]?.timestamp;

  return (
    <AppShell>
      <div className="space-y-8 pb-8">
        {/* ========================================================
            A. COMMAND & WELCOME SECTION
            ======================================================== */}
        <section
          aria-label="Welcome and Operations Header"
          className="relative overflow-hidden rounded-2xl border border-[var(--border-strong)] bg-gradient-to-br from-[var(--surface-elevated)] via-[var(--surface)] to-[var(--background-secondary)] p-6 sm:p-8 shadow-md"
        >
          {/* Subtle cyber background line accent */}
          <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-[var(--primary-orange-glow)] blur-3xl opacity-60" />

          <div className="relative z-10 max-w-4xl space-y-4">
            {/* Status indicator kicker */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] px-3 py-1 font-semibold text-[var(--primary-orange)]">
                <ShieldCheck className="h-3.5 w-3.5" />
                <span>Midnight Intelligence Workspace</span>
              </span>

              {user ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--status-success-border)] bg-[var(--status-success-bg)] px-3 py-1 text-[var(--status-success)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-success)]" />
                  <span>Cloud Vault Active &middot; RLS Enforced</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] px-3 py-1 text-[var(--status-warning)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-warning)]" />
                  <span>Guest Analyst Session &middot; Volatile RAM</span>
                </span>
              )}
            </div>

            {/* Core headline with identity greeting */}
            <div className="space-y-2">
              <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-[var(--foreground)] leading-tight">
                {user ? (
                  <>
                    Welcome back,{' '}
                    <span className="text-[var(--primary-orange)]">
                      {profile?.display_name || user.email?.split('@')[0] || 'Analyst'}
                    </span>
                    .
                  </>
                ) : (
                  <>Security Operations Workspace</>
                )}
                <br />
                <span className="bg-gradient-to-r from-[var(--primary-orange)] via-[var(--accent-amber)] to-[var(--accent-cyan)] bg-clip-text text-transparent">
                  See the signal. Understand the threat. Take action.
                </span>
              </h2>

              <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed max-w-2xl">
                AegisFlow delivers automated threat triage, multimodal OCR document inspection, and evidence-grounded claim analysis engineered to neutralize social engineering before compromise.
              </p>
            </div>

            {/* Direct action bar */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <Link
                href="/analyze"
                className="inline-flex items-center gap-2.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] px-5 py-3 text-xs sm:text-sm font-semibold shadow-md shadow-[var(--primary-orange-glow)] transition-all duration-150 cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px]"
              >
                <ShieldAlert className="h-4 w-4" />
                <span>Begin New Investigation</span>
                <ArrowRight className="h-4 w-4" />
              </Link>

              <Link
                href="/investigations"
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-3 text-xs sm:text-sm font-medium text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px] shadow-sm"
              >
                <Database className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>Investigation Vault {savedCount !== null ? `(${savedCount})` : ''}</span>
              </Link>

              <Link
                href="/academy"
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-3 text-xs sm:text-sm font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px]"
              >
                <GraduationCap className="h-4 w-4 text-[var(--accent-violet)]" />
                <span>Security Academy</span>
              </Link>
            </div>
          </div>
        </section>

        {/* ========================================================
            B. INTELLIGENCE OVERVIEW (GENUINE METRICS ONLY)
            ======================================================== */}
        <section aria-label="Intelligence Metrics Overview" className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
              <Activity className="h-4 w-4 text-[var(--primary-orange)]" />
              <span>Verified Operations Posture</span>
            </h3>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
              {user ? 'Cloud-Synchronized' : 'Local Memory Scope'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Saved Cases */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
                <span className="font-medium">Saved Investigations</span>
                <Database className="h-4 w-4 text-[var(--primary-orange)]" />
              </div>
              <div className="my-3">
                {authLoading || loadingCases ? (
                  <div className="h-7 w-16 bg-[var(--surface-interactive)] rounded animate-pulse" />
                ) : (
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-2xl sm:text-3xl font-extrabold text-[var(--foreground)] tabular-nums">
                      {user ? (savedCount ?? 0) : sessionAnalyses.length}
                    </span>
                    <span className="text-xs font-mono text-[var(--muted-foreground)]">
                      {user ? 'in Vault' : 'in Session'}
                    </span>
                  </div>
                )}
              </div>
              <p className="text-[11px] font-mono text-[var(--foreground-secondary)]">
                {user ? 'Row Level Security Verified' : 'Volatile Client Storage'}
              </p>
            </div>

            {/* Card 2: Recent Triage Activity */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
                <span className="font-medium">Last Triage Event</span>
                <Clock className="h-4 w-4 text-[var(--accent-cyan)]" />
              </div>
              <div className="my-3">
                {authLoading || loadingCases ? (
                  <div className="h-7 w-24 bg-[var(--surface-interactive)] rounded animate-pulse" />
                ) : (
                  <span className="font-mono text-lg sm:text-xl font-bold text-[var(--foreground)] truncate block">
                    {lastActivityTimestamp
                      ? formatRelativeTime(lastActivityTimestamp)
                      : 'No activity yet'}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-[var(--foreground-secondary)] truncate">
                {lastActivityTimestamp
                  ? `Recorded ${formatCaseDate(lastActivityTimestamp)}`
                  : 'Run an analysis to log activity'}
              </p>
            </div>

            {/* Card 3: Verified Case Threat Posture */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
                <span className="font-medium">Threat Distribution</span>
                <ShieldAlert className="h-4 w-4 text-[var(--accent-amber)]" />
              </div>
              <div className="my-3">
                {authLoading || loadingCases ? (
                  <div className="h-7 w-20 bg-[var(--surface-interactive)] rounded animate-pulse" />
                ) : user && savedCases.length > 0 ? (
                  <div className="flex items-center gap-2 font-mono text-xs font-bold">
                    <span className="text-[var(--status-critical)]">{highRiskCount} High</span>
                    <span className="text-[var(--muted-foreground)]">&middot;</span>
                    <span className="text-[var(--status-warning)]">{medRiskCount} Med</span>
                    <span className="text-[var(--muted-foreground)]">&middot;</span>
                    <span className="text-[var(--status-success)]">{lowRiskCount} Low</span>
                  </div>
                ) : !user && sessionAnalyses.length > 0 ? (
                  <span className="font-mono text-xs font-bold text-[var(--primary-orange)]">
                    {sessionAnalyses.length} Session Case(s)
                  </span>
                ) : (
                  <span className="text-xs font-mono text-[var(--muted-foreground)]">
                    Awaiting first submission
                  </span>
                )}
              </div>
              <p className="text-[11px] text-[var(--foreground-secondary)] truncate">
                {user && savedCases.length > 0
                  ? 'Based on recent vault dossiers'
                  : 'Calculated from user inputs'}
              </p>
            </div>

            {/* Card 4: Data Governance & Isolation */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
                <span className="font-medium">Data Isolation Tier</span>
                <Lock className="h-4 w-4 text-[var(--status-success)]" />
              </div>
              <div className="my-3">
                <span className="font-mono text-sm sm:text-base font-bold text-[var(--foreground)] truncate block">
                  {user ? 'Private User Vault' : 'Zero-Retention Mode'}
                </span>
              </div>
              <p className="text-[11px] font-mono text-[var(--foreground-secondary)] truncate">
                {user ? 'PostgreSQL RLS Active' : 'Cleared on session exit'}
              </p>
            </div>
          </div>
        </section>

        {/* ========================================================
            C. PRIMARY INVESTIGATION WORKSPACE (3 CORE WORKFLOWS)
            ======================================================== */}
        <section aria-label="Investigation Workspaces" className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
            <div>
              <h3 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
                <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>Primary Investigation Vectors</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Specialized multimodal analyzers calibrated against social engineering heuristics.
              </p>
            </div>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
              Select an investigation vector
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Workflow 1: Suspicious Message Analysis */}
            <Link
              href="/analyze"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--primary-orange)]/50 hover:bg-[var(--surface-interactive)] p-5 sm:p-6 transition-all duration-200 flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="h-10 w-10 rounded-xl bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <ShieldAlert className="h-5 w-5" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] text-[var(--primary-orange)]">
                    Direct Message
                  </span>
                </div>

                <div>
                  <h4 className="text-base font-bold text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors">
                    Suspicious Message Analyzer
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Evaluate urgent smishing SMS, CEO gift-card BEC schemes, and coercive banking alerts with automated IOC defanging.
                  </p>
                </div>

                <ul className="space-y-1.5 text-[11px] text-[var(--muted-foreground)] pt-2 border-t border-[var(--border-subtle)]">
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--primary-orange)]" />
                    <span>Automated URL, email &amp; phone defanging</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--primary-orange)]" />
                    <span>Behavioral OTP interception heuristics</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--primary-orange)]" />
                    <span>Evidence-sufficiency calibrated confidence</span>
                  </li>
                </ul>
              </div>

              <div className="mt-5 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--primary-orange)] group-hover:translate-x-0.5 transition-transform flex items-center gap-1.5">
                  <span>Launch Message Analyzer</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">Qwen3-VL-8B</span>
              </div>
            </Link>

            {/* Workflow 2: Document & Screenshot Threat Scanner */}
            <Link
              href="/analyze?tab=document"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--accent-cyan)]/50 hover:bg-[var(--surface-interactive)] p-5 sm:p-6 transition-all duration-200 flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="h-10 w-10 rounded-xl bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <UploadCloud className="h-5 w-5" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]">
                    Multimodal Vision
                  </span>
                </div>

                <div>
                  <h4 className="text-base font-bold text-[var(--foreground)] group-hover:text-[var(--accent-cyan)] transition-colors">
                    Document &amp; Screenshot Scanner
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Upload PDF invoices, account suspension letters, or chat screenshots for visual OCR extraction and prompt-injection defense.
                  </p>
                </div>

                <ul className="space-y-1.5 text-[11px] text-[var(--muted-foreground)] pt-2 border-t border-[var(--border-subtle)]">
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)]" />
                    <span>PDF magic-byte validation &amp; layout extraction</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)]" />
                    <span>Prompt injection isolation defenses</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)]" />
                    <span>Fact vs. inference threat boundary</span>
                  </li>
                </ul>
              </div>

              <div className="mt-5 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--accent-cyan)] group-hover:translate-x-0.5 transition-transform flex items-center gap-1.5">
                  <span>Launch Document Scanner</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">Vision OCR</span>
              </div>
            </Link>

            {/* Workflow 3: Evidence-Based Web Fact-Checker */}
            <Link
              href="/analyze?tab=factcheck"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--accent-violet)]/50 hover:bg-[var(--surface-interactive)] p-5 sm:p-6 transition-all duration-200 flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="h-10 w-10 rounded-xl bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Globe className="h-5 w-5" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)]">
                    URLhaus Grounded
                  </span>
                </div>

                <div>
                  <h4 className="text-base font-bold text-[var(--foreground)] group-hover:text-[var(--accent-violet)] transition-colors">
                    Web-Research Fact-Checker
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Cross-examine deceptive claims and suspicious domains against live authenticated web sources and malware threat databases.
                  </p>
                </div>

                <ul className="space-y-1.5 text-[11px] text-[var(--muted-foreground)] pt-2 border-t border-[var(--border-subtle)]">
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-violet)]" />
                    <span>Pre-search claim assessability screening</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-violet)]" />
                    <span>SSRF &amp; loopback protected threat checks</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-violet)]" />
                    <span>Citation grounding with snippet distinction</span>
                  </li>
                </ul>
              </div>

              <div className="mt-5 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--accent-violet)] group-hover:translate-x-0.5 transition-transform flex items-center gap-1.5">
                  <span>Launch Claim Fact-Checker</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">Serper &middot; URLhaus</span>
              </div>
            </Link>
          </div>
        </section>

        {/* ========================================================
            D. RECENT INVESTIGATIONS (SAVED VAULT VS GUEST MEMORY)
            ======================================================== */}
        {user ? (
          /* AUTHENTICATED USER: Saved Cloud Vault Cases */
          <section aria-label="Saved Cloud Investigations" className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
              <div>
                <h3 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
                  <Database className="h-4 w-4 text-[var(--primary-orange)]" />
                  <span>
                    Recent Investigation Dossiers {savedCount !== null ? `(${savedCount} Total in Vault)` : ''}
                  </span>
                </h3>
                <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                  Encrypted investigation history for <strong className="text-[var(--foreground)]">{profile?.display_name || user.email}</strong>, secured with PostgreSQL Row Level Security.
                </p>
              </div>

              <div className="flex items-center gap-2 self-start sm:self-auto">
                <button
                  type="button"
                  onClick={fetchUserCases}
                  disabled={loadingCases}
                  title="Reload recent investigations"
                  className="inline-flex items-center justify-center h-8 w-8 rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)] transition-colors cursor-pointer"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${loadingCases ? 'animate-spin' : ''}`} />
                </button>

                <Link
                  href="/investigations"
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] px-3 py-1.5 text-xs font-semibold text-[var(--primary-orange)] hover:bg-[var(--primary-orange)] hover:text-white transition-colors"
                >
                  <span>Open Full Investigation Vault</span>
                  <ArrowRight className="h-3 w-3" />
                </Link>
              </div>
            </div>

            {loadingCases ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className="h-24 rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 animate-pulse flex flex-col justify-between"
                  >
                    <div className="flex items-center gap-3">
                      <div className="h-5 w-24 bg-[var(--surface-interactive)] rounded" />
                      <div className="h-5 w-16 bg-[var(--surface-interactive)] rounded" />
                    </div>
                    <div className="h-4 bg-[var(--surface-interactive)] rounded w-3/4" />
                  </div>
                ))}
              </div>
            ) : casesError ? (
              <div className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-5 text-xs text-[var(--status-critical)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm">
                <div>
                  <span className="font-semibold block text-sm">Unable to retrieve saved cases</span>
                  <p className="mt-0.5 text-[var(--foreground-secondary)]">{casesError}</p>
                </div>
                <button
                  type="button"
                  onClick={fetchUserCases}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--status-critical)] text-white px-3.5 py-1.5 font-semibold text-xs transition-colors shrink-0 cursor-pointer"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  <span>Retry Query</span>
                </button>
              </div>
            ) : savedCases.length > 0 ? (
              <div className="space-y-3">
                {savedCases.map((item) => (
                  <div
                    key={item.id}
                    className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 transition-all duration-150 hover:border-[var(--primary-orange)]/40 hover:bg-[var(--surface-interactive)] flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm"
                  >
                    <div className="flex-1 min-w-0 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <ThreatBadge
                          level={item.threat_severity}
                          score={item.severity_score}
                          showScore
                          size="sm"
                        />
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[var(--surface-interactive)] text-[var(--muted-foreground)] border border-[var(--border)]">
                          {item.input_type || 'message'}
                        </span>
                        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                          &middot; {formatCaseDate(item.created_at)}
                        </span>
                      </div>

                      <p className="font-mono text-xs sm:text-sm text-[var(--foreground)] truncate font-medium">
                        &ldquo;{item.input_snippet}&rdquo;
                      </p>

                      <p className="text-xs text-[var(--foreground-secondary)] line-clamp-2 leading-relaxed">
                        {item.summary}
                      </p>
                    </div>

                    <div className="shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border-subtle)]">
                      <Link
                        href="/investigations"
                        className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-semibold text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors shadow-sm min-h-[38px]"
                      >
                        <span>Open in Vault</span>
                        <ArrowRight className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* Authenticated Empty State */
              <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--card-bg)] p-8 sm:p-12 text-center space-y-3 shadow-sm">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)]">
                  <Database className="h-6 w-6" />
                </div>
                <div className="space-y-1 max-w-md mx-auto">
                  <h4 className="text-base font-bold text-[var(--foreground)]">
                    Your Private Investigation Vault is Empty
                  </h4>
                  <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Analyses conducted while authenticated are automatically secured with row-level encryption. Submit your first suspicious message or upload a document to initialize your vault.
                  </p>
                </div>
                <div className="pt-2">
                  <Link
                    href="/analyze"
                    className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-semibold text-[var(--primary-foreground)] shadow-sm shadow-[var(--primary-orange-glow)] transition-colors min-h-[40px]"
                  >
                    <ShieldAlert className="h-4 w-4" />
                    <span>Run Your First Analysis</span>
                  </Link>
                </div>
              </div>
            )}
          </section>
        ) : (
          /* GUEST / UNAUTHENTICATED USER: Session Memory & Sign-in Callout */
          <section aria-label="Session Analyses" className="space-y-4">
            {/* Guest notice and persistent storage CTA */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
              <div className="space-y-1 max-w-xl">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] text-[var(--status-warning)]">
                    Volatile Memory
                  </span>
                  <h4 className="text-sm sm:text-base font-bold text-[var(--foreground)]">
                    Analyses stored in temporary session memory
                  </h4>
                </div>
                <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                  Submissions are held locally in volatile browser storage and will be cleared when your tab closes. Sign in to automatically archive cases to your private, encrypted cloud vault.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <Link
                  href="/auth/login?next=/"
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2 text-xs font-semibold text-[var(--primary-foreground)] shadow-sm shadow-[var(--primary-orange-glow)] transition-colors min-h-[40px]"
                >
                  <LogIn className="h-3.5 w-3.5" />
                  <span>Sign In</span>
                </Link>
                <Link
                  href="/auth/register"
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-2 text-xs font-medium text-[var(--foreground)] transition-colors min-h-[40px] shadow-sm"
                >
                  <UserPlus className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
                  <span>Register Account</span>
                </Link>
              </div>
            </div>

            {/* In-Session Records List */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2.5">
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-[var(--foreground)] flex items-center gap-2">
                    <Clock className="h-4 w-4 text-[var(--primary-orange)]" />
                    <span>In-Session Analyses ({sessionAnalyses.length})</span>
                  </h3>
                </div>

                {sessionAnalyses.length > 0 && (
                  <button
                    type="button"
                    onClick={handleClearHistory}
                    className="text-[11px] font-mono text-[var(--muted-foreground)] hover:text-[var(--status-critical)] transition-colors cursor-pointer"
                  >
                    Clear session memory
                  </button>
                )}
              </div>

              {sessionAnalyses.length > 0 ? (
                <div className="space-y-3">
                  {sessionAnalyses.map((item) => (
                    <div
                      key={item.id}
                      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-5 transition-all hover:border-[var(--primary-orange)]/40 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm"
                    >
                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <ThreatBadge
                            level={item.riskLevel}
                            score={item.severityScore}
                            showScore
                            size="sm"
                          />
                          <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                            &middot; {item.timestamp}
                          </span>
                        </div>

                        <p className="font-mono text-xs sm:text-sm text-[var(--foreground)] truncate font-medium">
                          &ldquo;{item.snippet}&rdquo;
                        </p>

                        <p className="text-xs text-[var(--foreground-secondary)] line-clamp-2 leading-relaxed">
                          {item.summary}
                        </p>
                      </div>

                      <div className="shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border-subtle)]">
                        <Link
                          href="/analyze"
                          className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-semibold text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors shadow-sm min-h-[38px]"
                        >
                          <span>Analyze Again</span>
                          <ArrowRight className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-8 text-center shadow-sm space-y-2.5">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--surface-interactive)] border border-[var(--border)] text-[var(--muted-foreground)]">
                    <FileText className="h-6 w-6" />
                  </div>
                  <h4 className="text-sm font-bold text-[var(--foreground)]">
                    No analyses recorded in this session yet
                  </h4>
                  <p className="text-xs text-[var(--foreground-secondary)] max-w-md mx-auto leading-relaxed">
                    Submit any suspicious SMS text, unexpected executive wire request, or unfamiliar URL in the AI Analyzer to inspect behavioral threat indicators.
                  </p>
                  <div className="pt-2">
                    <Link
                      href="/analyze"
                      className="inline-flex items-center gap-2 rounded-xl bg-[var(--surface-soft-orange)] hover:bg-[var(--primary-orange)] hover:text-white border border-[var(--primary-orange)]/30 px-4 py-2 text-xs font-semibold text-[var(--primary-orange)] transition-colors cursor-pointer min-h-[40px]"
                    >
                      <ShieldAlert className="h-4 w-4" />
                      <span>Launch AI Analyzer</span>
                    </Link>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ========================================================
            E. LEARNING & INTELLIGENCE ECOSYSTEM (DISCOVERY)
            ======================================================== */}
        <section aria-label="Learning and Intelligence Ecosystem" className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 border-b border-[var(--border-subtle)] pb-2.5">
            <div>
              <h3 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
                <GraduationCap className="h-4 w-4 text-[var(--accent-violet)]" />
                <span>Threat Literacy &amp; Intelligence Ecosystem</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Educational safety playbooks and structured cyber threat frameworks.
              </p>
            </div>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
              Curated Reference Materials
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Card 1: Security Academy */}
            <Link
              href="/academy"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--accent-violet)]/50 hover:bg-[var(--surface-interactive)] p-5 transition-all flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="h-9 w-9 rounded-xl bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <GraduationCap className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded border border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)]">
                    {verifiedAcademyCount > 0 ? `${verifiedAcademyCount}/4 Verified` : '4 Modules'}
                  </span>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-[var(--foreground)] group-hover:text-[var(--accent-violet)] transition-colors">
                    Security Academy &middot; Threat Checks
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Practice identifying bank smishing, business email compromise, package lures, and crypto extortion across 12 scenario-based quizzes.
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--accent-violet)] flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                  <span>Enter Academy</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">Interactive</span>
              </div>
            </Link>

            {/* Card 2: MITRE ATT&CK Matrix */}
            <Link
              href="/threat-intel"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--accent-amber)]/50 hover:bg-[var(--surface-interactive)] p-5 transition-all flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="h-9 w-9 rounded-xl bg-[var(--accent-amber-subtle)] text-[var(--accent-amber)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Binary className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded border border-[var(--accent-amber)]/30 bg-[var(--accent-amber-subtle)] text-[var(--accent-amber)]">
                    Framework
                  </span>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-[var(--foreground)] group-hover:text-[var(--accent-amber)] transition-colors">
                    MITRE ATT&CK Reference Taxonomy
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    Explore structured attack matrices covering Spearphishing Link (T1566.002), Voice Phishing (T1566.004), and Internal Impersonation.
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--accent-amber)] flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                  <span>Explore ATT&CK Matrix</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">Reference</span>
              </div>
            </Link>

            {/* Card 3: Investigation Vault */}
            <Link
              href="/investigations"
              className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--primary-orange)]/50 hover:bg-[var(--surface-interactive)] p-5 transition-all flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="h-9 w-9 rounded-xl bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <SearchCode className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] text-[var(--primary-orange)]">
                    Evidence Vault
                  </span>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors">
                    Cryptographic Case Vault
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    User-isolated case files with Indicator of Compromise (IOC) timelines, evidentiary defense chains, and forensic dossier exports.
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--primary-orange)] flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                  <span>Open Vault Explorer</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">RLS Protected</span>
              </div>
            </Link>
          </div>
        </section>

        {/* ========================================================
            F. VERIFIABLE PLATFORM TELEMETRY & SYSTEM STATUS
            ======================================================== */}
        <section
          aria-label="Platform Telemetry"
          className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6 shadow-sm space-y-3"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-[var(--status-success)]" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)]">
                Verifiable Infrastructure Configuration
              </h4>
            </div>
            <Link
              href="/settings"
              className="text-[11px] font-mono text-[var(--primary-orange)] hover:underline flex items-center gap-1 self-start sm:self-auto"
            >
              <Sliders className="h-3 w-3" />
              <span>Inspect Platform Diagnostics &rarr;</span>
            </Link>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 space-y-1">
              <span className="text-[10px] font-mono text-[var(--muted-foreground)] block uppercase">
                Active AI Inference Model
              </span>
              <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
                Qwen3-VL-8B-Instruct
              </span>
              <span className="text-[10px] text-[var(--foreground-secondary)] block">
                Upstream Provider: Featherless AI
              </span>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 space-y-1">
              <span className="text-[10px] font-mono text-[var(--muted-foreground)] block uppercase">
                Persistence &amp; RLS Engine
              </span>
              <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
                {user ? 'Supabase PostgreSQL' : 'Volatile Client RAM'}
              </span>
              <span className="text-[10px] text-[var(--foreground-secondary)] block">
                {user ? 'User-Isolated Row Level Security' : 'Session-Bounded Retention'}
              </span>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 space-y-1">
              <span className="text-[10px] font-mono text-[var(--muted-foreground)] block uppercase">
                Threat Intelligence Feeds
              </span>
              <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
                URLhaus &middot; Serper Grounding
              </span>
              <span className="text-[10px] text-[var(--foreground-secondary)] block">
                SSRF-Protected Server Proxy
              </span>
            </div>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
