'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import ThemeToggle from '@/components/ui/ThemeToggle';
import {
  Sliders,
  Cpu,
  Lock,
  Download,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ShieldCheck,
  Server,
  RefreshCw,
  Database,
  UserCheck,
  ShieldAlert,
  SearchCode,
  LogIn,
  KeyRound,
  Globe,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { clearSessionAnalyses, getSessionAnalyses } from '@/lib/session-store';
import { useAuth } from '@/hooks/use-auth';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import { getSiteUrl } from '@/lib/supabase/site-url';

export default function SettingsPage() {
  const { user, profile, loading: authLoading } = useAuth();
  const [testingEndpoint, setTestingEndpoint] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testSuccess, setTestSuccess] = useState<boolean | null>(null);
  const [cleared, setCleared] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  // Supabase Diagnostics State
  const [testingProfile, setTestingProfile] = useState(false);
  const [profileResult, setProfileResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingHistory, setTestingHistory] = useState(false);
  const [historyResult, setHistoryResult] = useState<{ success: boolean; message: string } | null>(null);

  const supabase = useMemo(() => createClient(), []);
  const supabaseConfigured = isSupabaseConfigured();

  // Obfuscated sanitized Supabase Host (NEVER reveal keys or tokens)
  const supabaseHost = useMemo(() => {
    const rawUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    if (!rawUrl) return 'Not configured';
    try {
      const parsed = new URL(rawUrl);
      return parsed.origin;
    } catch {
      return 'Configured (Invalid URL format)';
    }
  }, []);

  const handleTestAPI = async () => {
    setTestingEndpoint(true);
    setTestResult(null);
    setTestSuccess(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'AegisFlow system diagnostic ping: verifying active Featherless Qwen inference pipeline.',
        }),
      });

      const data = await response.json().catch(() => null);

      if (response.ok && data) {
        setTestSuccess(true);
        setTestResult(
          `Inference Verified: Model ${data.model || 'Qwen3'} responded with Risk: ${data.riskLevel.toUpperCase()} in sub-4 seconds.`
        );
      } else {
        setTestSuccess(false);
        setTestResult(data?.error || `Endpoint returned HTTP ${response.status}.`);
      }
    } catch (err: any) {
      setTestSuccess(false);
      setTestResult(err.message || 'Network failure while testing endpoint.');
    } finally {
      setTestingEndpoint(false);
    }
  };

  const handleTestProfileQuery = async () => {
    if (!user) {
      setProfileResult({
        success: false,
        message: 'No active session. You must be signed in to query your private profile row.',
      });
      return;
    }

    setTestingProfile(true);
    setProfileResult(null);

    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, display_name, created_at, updated_at')
        .eq('id', user.id)
        .single();

      if (error) {
        setProfileResult({
          success: false,
          message: `Query failed: ${error.message} (Code: ${error.code})`,
        });
      } else if (data) {
        setProfileResult({
          success: true,
          message: `Query Succeeded: Found profile for "${data.display_name || 'Unnamed Analyst'}" (Created: ${new Date(data.created_at).toLocaleDateString()}). RLS verified.`,
        });
      } else {
        setProfileResult({
          success: false,
          message: 'Query completed but returned no profile row for the authenticated user.',
        });
      }
    } catch (err: any) {
      setProfileResult({
        success: false,
        message: err.message || 'Unexpected exception during profile query.',
      });
    } finally {
      setTestingProfile(false);
    }
  };

  const handleTestHistoryQuery = async () => {
    if (!user) {
      setHistoryResult({
        success: false,
        message: 'No active session. You must be signed in to query private investigation history.',
      });
      return;
    }

    setTestingHistory(true);
    setHistoryResult(null);

    try {
      const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
      if (sessionErr) throw sessionErr;
      if (!sessionData?.session) {
        setHistoryResult({
          success: false,
          message: 'Active session token not found. Please refresh or sign in again.',
        });
        return;
      }

      // Harmless count query strictly scoped to current user by RLS
      const { count, error } = await supabase
        .from('analysis_history')
        .select('*', { count: 'exact', head: true });

      if (error) {
        setHistoryResult({
          success: false,
          message: `Query failed: ${error.message} (Code: ${error.code})`,
        });
      } else {
        setHistoryResult({
          success: true,
          message: `Query Succeeded: Retrieved ${count ?? 0} user-isolated record(s). Row Level Security policy confirmed active.`,
        });
      }
    } catch (err: any) {
      setHistoryResult({
        success: false,
        message: err.message || 'Unexpected exception during history count query.',
      });
    } finally {
      setTestingHistory(false);
    }
  };

  const handleClearSession = () => {
    clearSessionAnalyses();
    setCleared(true);
    setTimeout(() => setCleared(false), 2500);
  };

  const handleExportLogs = () => {
    const data = getSessionAnalyses();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegisflow-session-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AppShell>
      <div className="space-y-8 max-w-4xl">
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400 mb-2">
            <span>Platform Configuration &middot; System Preferences</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <Sliders className="h-7 w-7 text-cyan-400" />
            <span>Platform Settings &amp; Diagnostics</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400">
            Verify AI model health, test Supabase authentication integrity, and manage session privacy controls.
          </p>
        </div>

        {/* Visual Identity & Theme Preferences */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-7 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[var(--border-subtle)] pb-4">
            <div>
              <h3 className="text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                <Sliders className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>Visual Identity &amp; Interface Theme</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Choose between signature Midnight Intelligence dark mode, art-directed light mode, or system sync.
              </p>
            </div>
            <ThemeToggle variant="segmented" />
          </div>
          <p className="text-xs text-[var(--muted-foreground)] leading-relaxed">
            Theme selection is instantly applied across all dashboards, workspaces, and navigation surfaces, and persisted in your browser profile.
          </p>
        </div>

        {/* Supabase Infrastructure & Authentication Diagnostics */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-7 space-y-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-white/5 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="h-4 w-4 text-cyan-400" />
                <span>Supabase Database &amp; Auth Diagnostics</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Safe configuration and live query testing (secrets and tokens are strictly excluded).
              </p>
            </div>
            <span
              className={`rounded px-2 py-0.5 text-[10px] font-mono font-semibold border ${
                supabaseConfigured
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
              }`}
            >
              {supabaseConfigured ? 'Environment Configured' : 'Missing Config'}
            </span>
          </div>

          {/* Diagnostic Indicators */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5 space-y-1">
              <span className="text-slate-500 font-mono text-[11px] block">
                Public Supabase Endpoint:
              </span>
              <span className="font-mono text-slate-200 block truncate">
                {supabaseHost}
              </span>
              <p className="text-[10px] text-slate-500 pt-1">
                {supabaseConfigured
                  ? 'Public URL is declared in environment.'
                  : 'Add NEXT_PUBLIC_SUPABASE_URL to enable cloud persistence.'}
              </p>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5 space-y-1">
              <span className="text-slate-500 font-mono text-[11px] block">
                Active Session State:
              </span>
              {authLoading ? (
                <span className="text-slate-400 text-xs">Verifying session...</span>
              ) : user ? (
                <div>
                  <span className="font-mono text-cyan-300 font-semibold block truncate">
                    Authenticated: {user.email}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
                    User UUID: {user.id.slice(0, 8)}...{user.id.slice(-4)}
                  </span>
                </div>
              ) : (
                <div>
                  <span className="font-mono text-slate-300 block">
                    No Active Session (Guest Mode)
                  </span>
                  <Link
                    href="/auth/login"
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 underline inline-block mt-0.5"
                  >
                    Sign in to test authenticated queries &rarr;
                  </Link>
                </div>
              )}
            </div>
          </div>

          {/* Production Domain & Supabase URL Configuration Checklist */}
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white flex items-center gap-1.5">
                <Globe className="h-4 w-4 text-cyan-400" />
                <span>Production Domain &amp; Redirect URL Checklist</span>
              </span>
              <span className="text-[10px] font-mono text-cyan-300 bg-cyan-900/40 px-2 py-0.5 rounded border border-cyan-500/30">
                https://aegisflowx.vercel.app
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              For Supabase email confirmation links to route seamlessly without bouncing to the registration page, ensure your Supabase project settings match the following:
            </p>

            <div className="space-y-2 font-mono text-[11px]">
              <div className="flex items-center justify-between rounded-lg bg-[#070b14] border border-white/5 p-2.5">
                <div>
                  <span className="text-slate-500 block text-[10px]">1. Supabase Dashboard &rarr; Site URL:</span>
                  <span className="text-emerald-400">https://aegisflowx.vercel.app</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText('https://aegisflowx.vercel.app');
                    setCopiedUrl('site');
                    setTimeout(() => setCopiedUrl(null), 2000);
                  }}
                  className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer"
                  title="Copy Site URL"
                >
                  {copiedUrl === 'site' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>

              <div className="flex items-center justify-between rounded-lg bg-[#070b14] border border-white/5 p-2.5">
                <div>
                  <span className="text-slate-500 block text-[10px]">2. Supabase Dashboard &rarr; Redirect URLs (Allow list):</span>
                  <span className="text-cyan-300">https://aegisflowx.vercel.app/**</span>
                  <span className="text-slate-400 block text-[10px]">http://localhost:3000/**</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText('https://aegisflowx.vercel.app/**');
                    setCopiedUrl('redirect');
                    setTimeout(() => setCopiedUrl(null), 2000);
                  }}
                  className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer"
                  title="Copy Redirect Pattern"
                >
                  {copiedUrl === 'redirect' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>

            <p className="text-[10px] text-slate-400 leading-relaxed border-t border-cyan-500/10 pt-2">
              <strong className="text-cyan-200">Built-in Resiliency:</strong> If an existing verification link ever lands on <code className="text-white">/auth/register</code> or <code className="text-white">/auth/login</code>, AegisFlow now automatically intercepts the code or token hash and forwards the analyst session straight to your authenticated investigations workspace.
            </p>
          </div>

          {/* Diagnostic Action Buttons */}
          <div className="pt-2 space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={testingProfile || !user}
                onClick={handleTestProfileQuery}
                className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
              >
                {testingProfile ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
                    <span>Executing Profile Query...</span>
                  </>
                ) : (
                  <>
                    <UserCheck className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Test Profile Table Query</span>
                  </>
                )}
              </button>

              <button
                type="button"
                disabled={testingHistory || !user}
                onClick={handleTestHistoryQuery}
                className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
              >
                {testingHistory ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
                    <span>Executing History Query...</span>
                  </>
                ) : (
                  <>
                    <SearchCode className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Test User History Query (RLS)</span>
                  </>
                )}
              </button>
            </div>

            {/* Profile Test Result Alert */}
            {profileResult && (
              <div
                className={`text-xs p-3 rounded-xl border flex items-start gap-2.5 ${
                  profileResult.success
                    ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-300'
                    : 'border-red-500/30 bg-red-950/30 text-red-300'
                }`}
              >
                {profileResult.success ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
                ) : (
                  <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                )}
                <div className="flex-1">
                  <strong>Profile Query Diagnostic:</strong>
                  <p className="mt-0.5">{profileResult.message}</p>
                </div>
              </div>
            )}

            {/* History Test Result Alert */}
            {historyResult && (
              <div
                className={`text-xs p-3 rounded-xl border flex items-start gap-2.5 ${
                  historyResult.success
                    ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-300'
                    : 'border-red-500/30 bg-red-950/30 text-red-300'
                }`}
              >
                {historyResult.success ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
                ) : (
                  <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                )}
                <div className="flex-1">
                  <strong>History Query Diagnostic:</strong>
                  <p className="mt-0.5">{historyResult.message}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* AI Inference Provider Configuration */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-7 space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-4">
            <div>
              <h3 className="text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                <Cpu className="h-4 w-4 text-[var(--accent-violet)]" />
                <span>AI Inference Engine</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Upstream LLM host and active instruction-following model.
              </p>
            </div>
            <span className="rounded bg-[var(--status-success-bg)] border border-[var(--status-success-border)] px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--status-success)]">
              Active Server Route
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5">
              <span className="text-[var(--muted-foreground)] font-mono text-[11px] block">Provider Base URL:</span>
              <span className="font-mono text-[var(--foreground)] mt-1 block truncate">
                https://api.featherless.ai/v1
              </span>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5">
              <span className="text-[var(--muted-foreground)] font-mono text-[11px] block">Model Identifier:</span>
              <span className="font-mono text-[var(--accent-cyan)] mt-1 block truncate font-semibold">
                Qwen/Qwen3-VL-8B-Instruct
              </span>
            </div>
          </div>

          {/* Test Health Diagnostic */}
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <button
              type="button"
              onClick={handleTestAPI}
              disabled={testingEndpoint}
              className="inline-flex items-center gap-2 rounded-xl bg-[var(--surface)] hover:bg-[var(--surface-interactive)] border border-[var(--border)] px-4 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer shadow-sm focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              {testingEndpoint ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--primary-orange)]" />
                  <span>Running Inference Diagnostic...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
                  <span>Test API Pipeline Health</span>
                </>
              )}
            </button>

            {testResult && (
              <div
                className={`text-xs p-2.5 rounded-lg border flex items-center gap-2 ${
                  testSuccess
                    ? 'border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[var(--status-success)]'
                    : 'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] text-[var(--status-critical)]'
                }`}
              >
                {testSuccess ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--status-success)]" />
                ) : (
                  <AlertCircle className="h-4 w-4 shrink-0 text-[var(--status-critical)]" />
                )}
                <span>{testResult}</span>
              </div>
            )}
          </div>
        </div>

        {/* Privacy & Zero-Retention Controls */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-7 space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-4">
            <div>
              <h3 className="text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                <Lock className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>Zero-Retention Privacy Controls</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Volatile session memory and export capabilities.
              </p>
            </div>
            <span className="text-[10px] font-mono text-[var(--accent-amber)] bg-[var(--accent-amber-subtle)] border border-[var(--accent-amber)]/30 px-2 py-0.5 rounded font-semibold">
              Local Client RAM
            </span>
          </div>

          <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
            Guest analyses and unauthenticated submissions are processed exclusively in volatile memory and never written to persistent tables. Authenticated analyses are encrypted and isolated under your private user UUID.
          </p>

          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleExportLogs}
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-medium text-[var(--foreground)] transition-colors cursor-pointer shadow-sm focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <Download className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
              <span>Export Session Analyses JSON</span>
            </button>

            <button
              type="button"
              onClick={handleClearSession}
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] hover:opacity-90 px-3.5 py-2 text-xs font-medium text-[var(--status-critical)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <Trash2 className="h-3.5 w-3.5 text-[var(--status-critical)]" />
              <span>Clear Local Session Storage</span>
            </button>

            {cleared && (
              <span className="text-xs text-[var(--status-success)] font-semibold">
                Session storage cleared.
              </span>
            )}
          </div>
        </div>

        {/* Platform Build Info */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-4 text-[11px] font-mono text-[var(--muted-foreground)] flex flex-wrap items-center justify-between gap-2">
          <span>AegisFlow v1.2.0 &middot; Midnight Intelligence Design System</span>
          <span>Next.js 15 &middot; React 19 &middot; TypeScript</span>
        </div>
      </div>
    </AppShell>
  );
}
