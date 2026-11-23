'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import ThemeToggle from '@/components/ui/ThemeToggle';
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Globe,
  RefreshCw,
  Loader2,
  Lock,
  ArrowLeft,
  Server,
  Zap,
  Radio,
  AlertCircle,
} from 'lucide-react';

interface DiagnosticState {
  overallStatus: 'operational' | 'degraded' | 'error';
  timestamp: string;
  adminUser?: string;
  authorization?: {
    authSource: string;
    role: string;
    userRolesTableStatus: string;
  };
  providers: {
    featherless: any;
    serper: any;
    urlhaus: any;
  };
  geminiFallback: {
    isConfigured: boolean;
    aiFallbackEnabled: boolean;
    searchFallbackEnabled: boolean;
    documentFallbackEnabled: boolean;
    model: string;
    status: string;
    diagnostic?: any;
    telemetry?: any;
  };
  activeModelConfig?: {
    primaryModel: string;
    fallbackTextModel: string;
    fallbackVisionModel: string;
    geminiFallbackModel: string;
  };
}

export default function AdminDiagnosticsClient() {
  const [data, setData] = useState<DiagnosticState | null>(null);
  const [loading, setLoading] = useState(true);
  const [unauthorized, setUnauthorized] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const fetchDiagnostics = async () => {
    try {
      setRefreshing(true);
      setErrorMsg('');
      const res = await fetch('/api/admin/diagnostics', {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });

      if (res.status === 401 || res.status === 403) {
        setUnauthorized(true);
        setData(null);
        return;
      }

      if (!res.ok) {
        throw new Error(`Failed to load diagnostics (HTTP ${res.status})`);
      }

      const json = await res.json();
      setData(json);
      setUnauthorized(false);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Error fetching provider diagnostics');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch('/api/admin/diagnostics', {
          headers: { Accept: 'application/json' },
          cache: 'no-store',
        });
        if (!active) return;

        if (res.status === 401 || res.status === 403) {
          setUnauthorized(true);
          setData(null);
          return;
        }

        if (!res.ok) {
          throw new Error(`Failed to load diagnostics (HTTP ${res.status})`);
        }

        const json = await res.json();
        if (!active) return;
        setData(json);
        setUnauthorized(false);
      } catch (err: any) {
        if (!active) return;
        setErrorMsg(err?.message || 'Error fetching provider diagnostics');
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const getStatusBadge = (status?: string, isConfigured?: boolean) => {
    if (!isConfigured && status === 'missing_configuration') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-medium bg-[var(--surface-interactive)] text-[var(--muted-foreground)] border border-[var(--border)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--muted-foreground)]" aria-hidden="true" />
          <span>Not Configured</span>
        </span>
      );
    }
    if (status === 'configured_and_reachable') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-[var(--status-success-bg)] text-[var(--status-success)] border border-[var(--status-success-border)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-success)]" aria-hidden="true" />
          <span>Operationally Verified</span>
        </span>
      );
    }
    if (status === 'rate_limit_exhausted') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-[var(--status-warning-bg)] text-[var(--status-warning)] border border-[var(--status-warning-border)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-warning)]" aria-hidden="true" />
          <span>Rate Limit / Quota</span>
        </span>
      );
    }
    if (status === 'provider_timeout') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-[var(--status-warning-bg)] text-[var(--status-warning)] border border-[var(--status-warning-border)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-warning)]" aria-hidden="true" />
          <span>Temporarily Unavailable (Timeout)</span>
        </span>
      );
    }
    if (status === 'authentication_failure') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-[var(--status-critical-bg)] text-[var(--status-critical)] border border-[var(--status-critical-border)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-critical)]" aria-hidden="true" />
          <span>Auth Rejected</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-medium bg-[var(--surface-interactive)] text-[var(--foreground-secondary)] border border-[var(--border)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--muted-foreground)]" aria-hidden="true" />
        <span>{status || 'Unknown'}</span>
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow p-4 sm:p-6 lg:p-10 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Top Header */}
        <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[var(--border)] pb-6">
          <div className="space-y-1.5">
            <div className="inline-flex items-center gap-2 rounded-md border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] px-2.5 py-0.5 text-[11px] font-mono font-semibold text-[var(--primary-orange)]">
              <Lock className="h-3.5 w-3.5" aria-hidden="true" />
              <span>CONFIDENTIAL // ADMINISTRATOR AREA ONLY</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] flex items-center gap-3 font-[family-name:var(--font-display)]">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)]">
                <Server className="h-5 w-5" aria-hidden="true" />
              </span>
              <span>Provider Intelligence &amp; Engine Telemetry</span>
            </h1>
            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-2xl">
              Internal provider health, active model identifiers, fallback routing, and real-time connectivity status.
              Restricted to authorized administrators.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <ThemeToggle />
            <button
              type="button"
              onClick={fetchDiagnostics}
              disabled={refreshing}
              className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
              <span>Run Probe</span>
            </button>
            <Link
              href="/settings"
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--surface)] hover:bg-[var(--surface-interactive)] border border-[var(--border)] px-3.5 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Back to Settings</span>
            </Link>
          </div>
        </header>

        {/* Loading State */}
        {loading && (
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-12 text-center space-y-4 shadow-[var(--shadow-sm)]">
            <Loader2 className="h-8 w-8 animate-spin text-[var(--primary-orange)] mx-auto" aria-hidden="true" />
            <p className="text-sm text-[var(--foreground-secondary)]">
              Verifying administrator authorization and probing backend providers...
            </p>
          </div>
        )}

        {/* Fetch Error State */}
        {!loading && !unauthorized && errorMsg && (
          <div
            role="alert"
            className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-5 text-xs text-[var(--status-critical)] flex items-start gap-3"
          >
            <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <strong className="font-semibold block">Failed to probe provider diagnostics</strong>
              <p className="mt-1 text-[var(--foreground)]">{errorMsg}</p>
            </div>
          </div>
        )}

        {/* Unauthorized State */}
        {!loading && unauthorized && (
          <div className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--card-bg)] p-8 text-center space-y-4 max-w-xl mx-auto my-12 shadow-[var(--shadow-md)]">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--status-critical-bg)] border border-[var(--status-critical-border)] text-[var(--status-critical)]">
              <ShieldAlert className="h-6 w-6" aria-hidden="true" />
            </div>
            <h2 className="text-lg font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Administrator Access Required
            </h2>
            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
              This area contains internal provider routing and infrastructure telemetry restricted exclusively to authorized administrators.
              Your current authenticated session does not hold administrative privileges.
            </p>
            <div className="pt-2">
              <Link
                href="/settings"
                className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors"
              >
                <span>Return to General Settings</span>
              </Link>
            </div>
          </div>
        )}

        {/* Authorized Diagnostics Content */}
        {!loading && !unauthorized && data && (
          <div className="space-y-6">
            {/* Platform Overview Banner */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-[var(--shadow-sm)]">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]">
                  <ShieldCheck className="h-6 w-6" aria-hidden="true" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-bold text-[var(--foreground)]">Overall Core System Status:</span>
                    <span
                      className={`text-xs font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                        data.overallStatus === 'operational'
                          ? 'bg-[var(--status-success-bg)] text-[var(--status-success)] border-[var(--status-success-border)]'
                          : 'bg-[var(--status-warning-bg)] text-[var(--status-warning)] border-[var(--status-warning-border)]'
                      }`}
                    >
                      {data.overallStatus}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--foreground-secondary)] mt-0.5 tabular-nums">
                    Authorized Session: <span className="font-mono text-[var(--foreground)]">{data.adminUser}</span> &middot; Last probed: {new Date(data.timestamp).toLocaleTimeString()}
                  </p>
                  {data.authorization && (
                    <p className="text-[11px] font-mono text-[var(--muted-foreground)] mt-1">
                      Role: <span className="text-[var(--foreground)]">{data.authorization.role}</span> &middot; Source: <span className="text-[var(--accent-cyan)]">{data.authorization.authSource}</span> &middot; user_roles table: <span className="text-[var(--foreground)]">{data.authorization.userRolesTableStatus}</span>
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* Provider Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {/* Primary AI Provider */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 space-y-4 shadow-[var(--shadow-sm)]">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]">
                      <Cpu className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                        Primary AI Inference
                      </h3>
                      <span className="text-[11px] font-mono text-[var(--accent-cyan)]">Featherless AI Gateway</span>
                    </div>
                  </div>
                  {getStatusBadge(data.providers.featherless?.status, data.providers.featherless?.isConfigured)}
                </div>

                <div className="space-y-2 text-xs border-t border-[var(--border-subtle)] pt-3">
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Active Model:</span>
                    <span className="font-mono text-[var(--foreground)] text-right break-all">{data.activeModelConfig?.primaryModel || 'Qwen/Qwen3-VL-8B-Instruct'}</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Architecture Role:</span>
                    <span className="font-mono text-[var(--accent-cyan)] text-right">Primary AI Reasoning (Text &amp; Vision)</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Probe Latency:</span>
                    <span className="font-mono text-[var(--foreground)] tabular-nums">{data.providers.featherless?.latencyMs ? `${data.providers.featherless.latencyMs} ms` : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1">
                    <span className="text-[var(--foreground-secondary)]">Status Detail:</span>
                    <span className="font-mono text-[var(--foreground-secondary)] truncate max-w-[220px]" title={data.providers.featherless?.message}>
                      {data.providers.featherless?.message || 'Ready'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Secondary Fallback AI Provider */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 space-y-4 shadow-[var(--shadow-sm)]">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-[var(--accent-violet-subtle)] border border-[var(--accent-violet)]/30 text-[var(--accent-violet)]">
                      <Zap className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                        Secondary AI Fallback
                      </h3>
                      <span className="text-[11px] font-mono text-[var(--accent-violet)]">Google Gemini API</span>
                    </div>
                  </div>
                  {getStatusBadge(data.geminiFallback?.diagnostic?.status || (data.geminiFallback?.isConfigured ? 'configured' : 'missing_configuration'), data.geminiFallback?.isConfigured)}
                </div>

                <div className="space-y-2 text-xs border-t border-[var(--border-subtle)] pt-3">
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Active Model:</span>
                    <span className="font-mono text-[var(--foreground)] text-right break-all">{data.geminiFallback?.model || 'gemini-3.8-flash'}</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Fallback Toggles:</span>
                    <span className="font-mono text-[var(--accent-violet)] text-right">
                      AI: {data.geminiFallback?.aiFallbackEnabled ? 'ON' : 'OFF'} &middot; Search: {data.geminiFallback?.searchFallbackEnabled ? 'ON' : 'OFF'} &middot; Doc: {data.geminiFallback?.documentFallbackEnabled ? 'ON' : 'OFF'}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Probe Latency:</span>
                    <span className="font-mono text-[var(--foreground)] tabular-nums">{data.geminiFallback?.diagnostic?.latencyMs ? `${data.geminiFallback.diagnostic.latencyMs} ms` : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1">
                    <span className="text-[var(--foreground-secondary)]">Status Detail:</span>
                    <span className="font-mono text-[var(--foreground-secondary)] truncate max-w-[220px]" title={data.geminiFallback?.diagnostic?.message}>
                      {data.geminiFallback?.diagnostic?.message || 'Fallback standby'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Primary Web Research */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 space-y-4 shadow-[var(--shadow-sm)]">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]">
                      <Globe className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                        Live Web Research
                      </h3>
                      <span className="text-[11px] font-mono text-[var(--accent-cyan)]">Serper.dev Web Search API</span>
                    </div>
                  </div>
                  {getStatusBadge(data.providers.serper?.status, data.providers.serper?.isConfigured)}
                </div>

                <div className="space-y-2 text-xs border-t border-[var(--border-subtle)] pt-3">
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Architecture Role:</span>
                    <span className="font-mono text-[var(--accent-cyan)] text-right">Primary External Search &amp; Fact Verification</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Probe Latency:</span>
                    <span className="font-mono text-[var(--foreground)] tabular-nums">{data.providers.serper?.latencyMs ? `${data.providers.serper.latencyMs} ms` : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1">
                    <span className="text-[var(--foreground-secondary)]">Grounding Fallback:</span>
                    <span className="font-mono text-[var(--foreground-secondary)] text-right">Gemini Google Search Grounding (Active Standby)</span>
                  </div>
                </div>
              </div>

              {/* Threat Intelligence Feed */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 space-y-4 shadow-[var(--shadow-sm)]">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-[var(--status-success-bg)] border border-[var(--status-success-border)] text-[var(--status-success)]">
                      <Radio className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                        Threat Intelligence
                      </h3>
                      <span className="text-[11px] font-mono text-[var(--status-success)]">URLhaus (abuse.ch API)</span>
                    </div>
                  </div>
                  {getStatusBadge(data.providers.urlhaus?.status, data.providers.urlhaus?.isConfigured)}
                </div>

                <div className="space-y-2 text-xs border-t border-[var(--border-subtle)] pt-3">
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Architecture Role:</span>
                    <span className="font-mono text-[var(--status-success)] text-right">Malware &amp; Phishing Domain Infrastructure Feed</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[var(--foreground-secondary)]">Isolation Invariant:</span>
                    <span className="font-mono text-[var(--foreground)] text-right">Dedicated Lookup (Decoupled from Search)</span>
                  </div>
                  <div className="flex justify-between gap-2 py-1">
                    <span className="text-[var(--foreground-secondary)]">Probe Latency:</span>
                    <span className="font-mono text-[var(--foreground)] tabular-nums">{data.providers.urlhaus?.latencyMs ? `${data.providers.urlhaus.latencyMs} ms` : 'N/A'}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Security Notice */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-4 text-xs text-[var(--foreground-secondary)] flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>API credentials, bearer tokens, and secret strings are stripped server-side and never returned over the network.</span>
              </span>
              <span className="font-mono text-[10px] text-[var(--muted-foreground)]">Security Invariant Enforced</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
