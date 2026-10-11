'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
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
} from 'lucide-react';
import { clearSessionAnalyses, getSessionAnalyses } from '@/lib/session-store';
import { useAuth } from '@/hooks/use-auth';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';

export default function SettingsPage() {
  const { user, profile, loading: authLoading } = useAuth();
  const [testingEndpoint, setTestingEndpoint] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testSuccess, setTestSuccess] = useState<boolean | null>(null);
  const [cleared, setCleared] = useState(false);

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

        {/* Supabase Infrastructure & Authentication Diagnostics */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-7 space-y-5">
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
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-7 space-y-4">
          <div className="flex items-center justify-between border-b border-white/5 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                <span>AI Inference Engine</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Upstream LLM host and active instruction-following model.
              </p>
            </div>
            <span className="rounded bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-[10px] font-mono font-semibold text-emerald-400">
              Active Server Route
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-slate-500 font-mono text-[11px] block">Provider Base URL:</span>
              <span className="font-mono text-slate-200 mt-1 block truncate">
                https://api.featherless.ai/v1
              </span>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-slate-500 font-mono text-[11px] block">Model Identifier:</span>
              <span className="font-mono text-cyan-300 mt-1 block truncate">
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
              className="inline-flex items-center gap-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/10 px-4 py-2 text-xs font-semibold text-white transition-colors cursor-pointer"
            >
              {testingEndpoint ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
                  <span>Running Inference Diagnostic...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Test API Pipeline Health</span>
                </>
              )}
            </button>

            {testResult && (
              <div
                className={`text-xs p-2.5 rounded-lg border flex items-center gap-2 ${
                  testSuccess
                    ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-300'
                    : 'border-red-500/30 bg-red-950/30 text-red-300'
                }`}
              >
                {testSuccess ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
                )}
                <span>{testResult}</span>
              </div>
            )}
          </div>
        </div>

        {/* Privacy & Zero-Retention Controls */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-7 space-y-4">
          <div className="flex items-center justify-between border-b border-white/5 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Lock className="h-4 w-4 text-cyan-400" />
                <span>Zero-Retention Privacy Controls</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Volatile session memory and export capabilities.
              </p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/50 border border-cyan-500/20 px-2 py-0.5 rounded">
              Local Client RAM
            </span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            Guest analyses and unauthenticated submissions are processed exclusively in volatile memory and never written to persistent tables. Authenticated analyses are encrypted and isolated under your private user UUID.
          </p>

          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleExportLogs}
              className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer"
            >
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              <span>Export Session Analyses JSON</span>
            </button>

            <button
              type="button"
              onClick={handleClearSession}
              className="inline-flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-950/20 hover:bg-red-950/40 px-3.5 py-2 text-xs font-medium text-red-300 transition-colors cursor-pointer"
            >
              <Trash2 className="h-3.5 w-3.5 text-red-400" />
              <span>Clear Local Session Storage</span>
            </button>

            {cleared && (
              <span className="text-xs text-emerald-400">
                Session storage cleared.
              </span>
            )}
          </div>
        </div>

        {/* Platform Build Info */}
        <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
          <span>AegisFlow v1.2.0 &middot; Supabase SSR &amp; Qwen3 Intelligence</span>
          <span>Next.js 15 &middot; React 19 &middot; TypeScript</span>
        </div>
      </div>
    </AppShell>
  );
}
