'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import PageHeader from '@/components/ui/PageHeader';
import { useAuth } from '@/hooks/use-auth';
import { createClient } from '@/lib/supabase/client';
import {
  SearchCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  ShieldQuestion,
  Lock,
  Database,
  Search,
  Trash2,
  Eye,
  X,
  RefreshCw,
  Loader2,
  Calendar,
  CheckCircle2,
  LogIn,
  UserPlus,
  FileText,
  AlertCircle,
  Copy,
  Check,
  Globe,
  Link2,
  MessageSquare,
} from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';

interface AnalysisHistoryRecord {
  id: string;
  user_id: string;
  input_type: string;
  input_snippet: string;
  threat_severity: 'high' | 'medium' | 'low' | 'uncertain';
  severity_score: number;
  summary: string;
  indicators: Array<{
    name: string;
    evidence: string;
    reason: string;
  }>;
  recommended_actions: string[];
  limitations: string[];
  evidence_sufficiency: 'sufficient' | 'moderate' | 'sparse';
  model_confidence: 'high' | 'moderate' | 'low';
  confidence_rationale?: string;
  model_name?: string;
  iocs?: {
    urls?: string[];
    emails?: string[];
    phoneNumbers?: string[];
    keywords?: string[];
    documentContent?: {
      detectedType?: string;
      extractedTextSnippet?: string;
      apparentSenderOrOrganization?: string;
      claimedPurpose?: string;
      filename?: string;
      fileSizeBytes?: number;
      mimeType?: string;
      pageCount?: number;
    };
    suspiciousElements?: Array<{
      category: string;
      evidence: string;
      explanation: string;
    }>;
    verificationStatus?: {
      independentlyVerified?: string[];
      unverifiedClaims?: string[];
    };
    factCheckReport?: any;
  };
  created_at: string;
}

export default function InvestigationsPage() {
  const { user, loading: authLoading, authState } = useAuth();
  const [records, setRecords] = useState<AnalysisHistoryRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState<boolean>(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AnalysisHistoryRecord | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const supabase = useMemo(() => createClient(), []);

  const handleManualRefresh = useCallback(async () => {
    if (!user) return;
    setLoadingRecords(true);
    setFetchError(null);
    try {
      const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
      if (sessionErr) throw sessionErr;
      if (!sessionData?.session) {
        setFetchError('Active session token not found. Please refresh the page or sign in again.');
        return;
      }

      const { data, error } = await supabase
        .from('analysis_history')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) {
        setFetchError(error.message);
      } else {
        setRecords((data as AnalysisHistoryRecord[]) || []);
      }
    } catch (err: any) {
      setFetchError(err.message || 'Failed to retrieve investigation records.');
    } finally {
      setLoadingRecords(false);
    }
  }, [supabase, user]);

  // Lock background scroll & support Escape to close dossier modal
  useEffect(() => {
    if (!selectedRecord) return;
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedRecord(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [selectedRecord]);

  useEffect(() => {
    if (authLoading || !user) {
      return;
    }

    let isMounted = true;

    const fetchCases = async () => {
      setLoadingRecords(true);
      setFetchError(null);
      try {
        const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
        if (sessionErr) throw sessionErr;
        if (!sessionData?.session) {
          return;
        }

        const { data, error } = await supabase
          .from('analysis_history')
          .select('*')
          .order('created_at', { ascending: false });

        if (!isMounted) return;
        if (error) {
          setFetchError(error.message);
        } else {
          setRecords((data as AnalysisHistoryRecord[]) || []);
        }
      } catch (err: any) {
        if (!isMounted) return;
        setFetchError(err.message || 'Failed to retrieve investigation records.');
      } finally {
        if (isMounted) {
          setLoadingRecords(false);
        }
      }
    };

    fetchCases();

    return () => {
      isMounted = false;
    };
  }, [authLoading, supabase, user]);

  const handleConfirmDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeletingId(id);
    setDeleteError(null);
    try {
      const { error } = await supabase
        .from('analysis_history')
        .delete()
        .eq('id', id);

      if (error) {
        setDeleteError(`Failed to delete record: ${error.message}`);
      } else {
        setRecords((prev) => prev.filter((r) => r.id !== id));
        if (selectedRecord?.id === id) {
          setSelectedRecord(null);
        }
        setConfirmDeleteId(null);
      }
    } catch (err: any) {
      setDeleteError(`Deletion error: ${err.message || 'Unexpected error'}`);
    } finally {
      setDeletingId(null);
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredRecords = useMemo(() => {
    return records.filter((record) => {
      const matchesSeverity =
        selectedSeverity === 'all' || record.threat_severity === selectedSeverity;
      const matchesType =
        selectedType === 'all' ||
        (selectedType === 'text'
          ? record.input_type === 'text' || !record.input_type
          : record.input_type === selectedType);
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        record.input_snippet.toLowerCase().includes(q) ||
        record.summary.toLowerCase().includes(q) ||
        (record.indicators &&
          record.indicators.some(
            (i) =>
              i.name.toLowerCase().includes(q) ||
              i.evidence.toLowerCase().includes(q) ||
              i.reason.toLowerCase().includes(q)
          ));
      return matchesSeverity && matchesType && matchesSearch;
    });
  }, [records, searchQuery, selectedSeverity, selectedType]);

  const stats = useMemo(() => {
    const total = records.length;
    const high = records.filter((r) => r.threat_severity === 'high').length;
    const medium = records.filter((r) => r.threat_severity === 'medium').length;
    const low = records.filter((r) => r.threat_severity === 'low').length;
    const uncertain = records.filter((r) => r.threat_severity === 'uncertain').length;
    const avgScore =
      total > 0
        ? Math.round(records.reduce((acc, r) => acc + (r.severity_score || 0), 0) / total)
        : 0;
    return { total, high, medium, low, uncertain, avgScore };
  }, [records]);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high':
        return {
          label: 'High Threat',
          bg: 'bg-[var(--status-critical-bg)] text-[var(--status-critical)] border-[var(--status-critical-border)]',
          icon: AlertOctagon,
        };
      case 'medium':
        return {
          label: 'Medium Risk',
          bg: 'bg-[var(--status-warning-bg)] text-[var(--status-warning)] border-[var(--status-warning-border)]',
          icon: AlertTriangle,
        };
      case 'low':
        return {
          label: 'Low / Safe',
          bg: 'bg-[var(--status-success-bg)] text-[var(--status-success)] border-[var(--status-success-border)]',
          icon: ShieldCheck,
        };
      default:
        return {
          label: 'Uncertain',
          bg: 'bg-[var(--status-uncertain-bg)] text-[var(--status-uncertain)] border-[var(--status-uncertain-border)]',
          icon: ShieldQuestion,
        };
    }
  };

  const getResearchStatusBadge = (record: AnalysisHistoryRecord) => {
    const report = record.iocs?.factCheckReport;
    const status = report?.searchProviderStatus?.researchStatus;
    const isBypassed =
      status === 'not_required' ||
      report?.hasVerifiableClaims === false ||
      record.model_name?.includes('Bypassed') ||
      record.model_name?.includes('Conversational');

    if (status === 'live_research_completed') {
      return {
        label: 'Live Web Research',
        className: 'bg-[var(--status-success-bg)] border-[var(--status-success-border)] text-[var(--status-success)]',
        dotClass: 'bg-[var(--status-success)]',
      };
    }
    if (status === 'completed_using_cached_evidence') {
      return {
        label: 'Pre-Cached Web Intelligence',
        className: 'bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]',
        dotClass: 'bg-[var(--accent-cyan)]',
      };
    }
    if (isBypassed) {
      return {
        label: 'External Search Bypassed',
        className: 'bg-[var(--surface-interactive)] border-[var(--border)] text-[var(--muted-foreground)]',
        dotClass: 'bg-[var(--muted-foreground)]',
      };
    }
    if (status === 'quota_exhausted') {
      return {
        label: 'Registry Fallback (Quota Limit)',
        className: 'bg-[var(--status-warning-bg)] border-[var(--status-warning-border)] text-[var(--status-warning)]',
        dotClass: 'bg-[var(--status-warning)]',
      };
    }
    if (status === 'provider_unavailable' || status === 'provider_timeout') {
      return {
        label: 'Offline Reference Fallback',
        className: 'bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30 text-[var(--accent-violet)]',
        dotClass: 'bg-[var(--accent-violet)]',
      };
    }
    if (record.input_type === 'url_investigation') {
      return {
        label: 'URL Intelligence',
        className: 'bg-[var(--surface-soft-orange)] border-[var(--primary-orange)]/30 text-[var(--primary-orange)]',
        dotClass: 'bg-[var(--primary-orange)]',
      };
    }
    if (record.input_type === 'fact_check') {
      return {
        label: 'Fact-Check Intelligence',
        className: 'bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]',
        dotClass: 'bg-[var(--accent-cyan)]',
      };
    }
    return {
      label: 'Threat Telemetry',
      className: 'bg-[var(--surface-interactive)] border-[var(--border)] text-[var(--foreground-secondary)]',
      dotClass: 'bg-[var(--muted-foreground)]',
    };
  };

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          breadcrumbLabel="Investigations"
          title="Threat Investigations"
          description="User-isolated case management, extracted Indicators of Compromise (IOCs), and forensic timelines."
          icon={SearchCode}
          badgeText="Personal Forensic Vault"
          badgeVariant="cyan"
          actions={
            user ? (
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleManualRefresh}
                  disabled={loadingRecords}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`h-3.5 w-3.5 text-[var(--accent-cyan)] ${loadingRecords ? 'animate-spin' : ''}`} aria-hidden="true" />
                  <span>Refresh Cases</span>
                </button>
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3.5 py-2 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors"
                >
                  <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>New Analysis</span>
                </Link>
              </div>
            ) : undefined
          }
        />

        {/* Initial Session Verification State */}
        {authState === 'loading' && (
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-12 text-center max-w-2xl mx-auto space-y-4 shadow-[var(--shadow-sm)]">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)]">
              <Loader2 className="h-6 w-6 animate-spin" aria-hidden="true" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                Verifying Secure Analyst Session
              </h2>
              <p className="text-xs text-[var(--foreground-secondary)] mt-1">
                Confirming credentials and checking Row Level Security (RLS) vault permissions...
              </p>
            </div>
          </div>
        )}

        {/* Unauthenticated State */}
        {authState === 'unauthenticated' && !user && (
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-8 sm:p-10 shadow-[var(--shadow-md)] text-center max-w-2xl mx-auto space-y-6">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)]">
              <Lock className="h-7 w-7" aria-hidden="true" />
            </div>

            <div>
              <h2 className="text-xl font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                Private Investigation Vault
              </h2>
              <p className="mt-2 text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
                You are currently exploring in <strong className="text-[var(--foreground)]">Guest Mode</strong> with zero-retention ephemeral memory. To retain persistent case histories, track IOC timelines, and access saved investigations across devices, sign in to your verified analyst workspace.
              </p>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 text-xs text-[var(--foreground-secondary)] text-left space-y-2">
              <div className="flex items-center gap-2 text-[var(--foreground)] font-semibold">
                <Database className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>Zero-Trust Database Isolation:</span>
              </div>
              <p className="text-[11px] leading-relaxed">
                All saved investigation records are bound strictly to your authenticated UUID and protected with PostgreSQL Row Level Security (RLS). No other user or guest can query your private case logs.
              </p>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/auth/login?next=/investigations"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer"
              >
                <LogIn className="h-4 w-4" aria-hidden="true" />
                <span>Sign In to Access Vault</span>
              </Link>
              <Link
                href="/auth/register"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-5 py-2.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
              >
                <UserPlus className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>Create Analyst Account</span>
              </Link>
            </div>
          </div>
        )}

        {/* Authenticated State */}
        {user && (
          <>
            {/* Case Metrics Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div className="rounded-xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 shadow-[var(--shadow-sm)]">
                <span className="text-[11px] font-mono text-[var(--muted-foreground)] block">Total Cases</span>
                <span className="text-xl font-bold text-[var(--foreground)] mt-1 block tabular-nums">{stats.total}</span>
              </div>
              <div className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3.5">
                <span className="text-[11px] font-mono text-[var(--status-critical)] block">High Threat</span>
                <span className="text-xl font-bold text-[var(--status-critical)] mt-1 block tabular-nums">{stats.high}</span>
              </div>
              <div className="rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3.5">
                <span className="text-[11px] font-mono text-[var(--status-warning)] block">Medium Risk</span>
                <span className="text-xl font-bold text-[var(--status-warning)] mt-1 block tabular-nums">{stats.medium}</span>
              </div>
              <div className="rounded-xl border border-[var(--status-success-border)] bg-[var(--status-success-bg)] p-3.5">
                <span className="text-[11px] font-mono text-[var(--status-success)] block">Safe / Low</span>
                <span className="text-xl font-bold text-[var(--status-success)] mt-1 block tabular-nums">{stats.low}</span>
              </div>
              <div className="rounded-xl border border-[var(--status-uncertain-border)] bg-[var(--status-uncertain-bg)] p-3.5">
                <span className="text-[11px] font-mono text-[var(--status-uncertain)] block">Uncertain</span>
                <span className="text-xl font-bold text-[var(--status-uncertain)] mt-1 block tabular-nums">{stats.uncertain}</span>
              </div>
              <div className="rounded-xl border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] p-3.5">
                <span className="text-[11px] font-mono text-[var(--accent-cyan)] block">Avg Severity</span>
                <span className="text-xl font-bold text-[var(--accent-cyan)] mt-1 block tabular-nums">{stats.avgScore}/100</span>
              </div>
            </div>

            {/* Inline Delete Error Banner */}
            {deleteError && (
              <div
                role="alert"
                className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3.5 text-xs text-[var(--status-critical)] flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{deleteError}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setDeleteError(null)}
                  aria-label="Dismiss error"
                  className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] cursor-pointer p-1"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            )}

            {/* Filter and Search Controls */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 shadow-[var(--shadow-sm)]">
              <div className="relative w-full lg:w-72">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[var(--muted-foreground)]" aria-hidden="true" />
                <input
                  type="text"
                  aria-label="Filter investigation records by keyword, URL, or IOC"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by keyword, URL, or IOC..."
                  className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] pl-9 pr-3 py-1.5 text-xs text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)]"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
                {/* Source Type Filter */}
                <div
                  role="group"
                  aria-label="Filter by source type"
                  className="flex items-center gap-1 rounded-xl bg-[var(--surface-interactive)] p-1 border border-[var(--border-subtle)] overflow-x-auto max-w-full"
                >
                  {[
                    { id: 'all', label: 'All Sources', Icon: null },
                    { id: 'url_investigation', label: 'URLs', Icon: Link2 },
                    { id: 'document', label: 'Documents', Icon: FileText },
                    { id: 'screenshot', label: 'Screenshots', Icon: Eye },
                    { id: 'fact_check', label: 'Fact-Checks', Icon: Globe },
                    { id: 'text', label: 'Messages', Icon: MessageSquare },
                  ].map((t) => {
                    const TabIcon = t.Icon;
                    const active = selectedType === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setSelectedType(t.id)}
                        className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer shrink-0 ${
                          active
                            ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                            : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface)]'
                        }`}
                      >
                        {TabIcon && <TabIcon className="h-3 w-3" aria-hidden="true" />}
                        <span>{t.label}</span>
                      </button>
                    );
                  })}
                </div>

                {/* Threat Severity Filter */}
                <div
                  role="group"
                  aria-label="Filter by threat severity"
                  className="flex items-center gap-1 rounded-xl bg-[var(--surface-interactive)] p-1 border border-[var(--border-subtle)] overflow-x-auto max-w-full"
                >
                  {['all', 'high', 'medium', 'low', 'uncertain'].map((sev) => {
                    const active = selectedSeverity === sev;
                    return (
                      <button
                        key={sev}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setSelectedSeverity(sev)}
                        className={`rounded-lg px-2.5 py-1 text-[11px] font-semibold capitalize transition-colors cursor-pointer shrink-0 ${
                          active
                            ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                            : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface)]'
                        }`}
                      >
                        {sev}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Error Message with Explanations & Retry Action */}
            {fetchError && (
              <div
                role="alert"
                className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-5 text-[var(--foreground)] space-y-3"
              >
                <div className="flex items-start gap-3">
                  <AlertCircle className="h-5 w-5 shrink-0 text-[var(--status-critical)] mt-0.5" aria-hidden="true" />
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-bold text-[var(--status-critical)]">
                      Failed to query investigation history
                    </h3>
                    <p className="mt-1 text-xs font-mono text-[var(--status-critical)] break-words bg-[var(--background-secondary)] p-2.5 rounded-lg border border-[var(--status-critical-border)]">
                      {fetchError}
                    </p>
                    {fetchError.toLowerCase().includes('permission denied') && (
                      <p className="mt-2 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                        Database permission error: The PostgreSQL role <code className="text-[var(--accent-cyan)] font-mono">authenticated</code> lacks table-level privileges on <code className="text-[var(--accent-cyan)] font-mono">public.analysis_history</code>. Execute migration <code className="text-[var(--accent-cyan)] font-mono">0002_fix_analysis_history_permissions.sql</code> in the Supabase SQL Editor to grant SELECT, INSERT, and DELETE privileges with ownership RLS.
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 pl-8 pt-1">
                  <button
                    type="button"
                    onClick={handleManualRefresh}
                    disabled={loadingRecords}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3.5 py-1.5 text-xs font-bold text-[var(--primary-foreground)] transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${loadingRecords ? 'animate-spin' : ''}`} aria-hidden="true" />
                    <span>{loadingRecords ? 'Retrying...' : 'Retry Loading History'}</span>
                  </button>
                  <Link
                    href="/settings?tab=diagnostics"
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-semibold text-[var(--foreground)] transition-colors"
                  >
                    <span>Database Diagnostics</span>
                  </Link>
                </div>
              </div>
            )}

            {/* Loading Skeleton */}
            {loadingRecords && (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className="h-28 rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 animate-pulse flex flex-col justify-between"
                  >
                    <div className="h-4 bg-[var(--surface-interactive)] rounded w-1/3" />
                    <div className="h-3 bg-[var(--surface-interactive)] rounded w-3/4" />
                    <div className="h-3 bg-[var(--surface-interactive)] rounded w-1/4" />
                  </div>
                ))}
              </div>
            )}

            {/* Empty State */}
            {!loadingRecords && !fetchError && filteredRecords.length === 0 && (
              <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--card-bg)] p-12 text-center space-y-4">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--surface-interactive)] border border-[var(--border)] text-[var(--accent-cyan)]">
                  <SearchCode className="h-6 w-6" aria-hidden="true" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                    {searchQuery || selectedSeverity !== 'all' || selectedType !== 'all'
                      ? 'No matching investigation records'
                      : 'No investigation records yet'}
                  </h3>
                  <p className="text-xs text-[var(--foreground-secondary)] mt-1 max-w-md mx-auto">
                    {searchQuery || selectedSeverity !== 'all' || selectedType !== 'all'
                      ? 'Try adjusting your search terms or filter settings.'
                      : 'Messages, documents, fact-checks, and URLs analyzed while authenticated are automatically recorded in this private vault.'}
                  </p>
                </div>
                <div>
                  <Link
                    href="/analyze"
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Analyze a Message Now</span>
                  </Link>
                </div>
              </div>
            )}

            {/* Records List */}
            {!loadingRecords && filteredRecords.length > 0 && (
              <div className="space-y-3">
                {filteredRecords.map((record) => {
                  const badge = getSeverityBadge(record.threat_severity);
                  const BadgeIcon = badge.icon;
                  const dateStr = new Date(record.created_at).toLocaleString();
                  const urlCount = record.iocs?.urls?.length || 0;
                  const emailCount = record.iocs?.emails?.length || 0;
                  const phoneCount = record.iocs?.phoneNumbers?.length || 0;
                  const isConfirming = confirmDeleteId === record.id;

                  return (
                    <article
                      key={record.id}
                      className="group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--primary-orange)]/40 p-4 sm:p-5 transition-colors shadow-[var(--shadow-sm)]"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                        <button
                          type="button"
                          onClick={() => setSelectedRecord(record)}
                          className="space-y-2 flex-1 min-w-0 text-left cursor-pointer focus-visible:outline-none"
                        >
                          {/* Badges line */}
                          <div className="flex flex-wrap items-center gap-2">
                            {record.input_type === 'url_investigation' ? (
                              <span className="inline-flex items-center gap-1 rounded-md bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 px-2 py-0.5 text-[10px] font-mono text-[var(--primary-orange)] font-bold">
                                <Link2 className="h-3 w-3" aria-hidden="true" />
                                <span>URL Intel</span>
                              </span>
                            ) : record.input_type === 'document' ? (
                              <span className="inline-flex items-center gap-1 rounded-md bg-[var(--accent-violet-subtle)] border border-[var(--accent-violet)]/30 px-2 py-0.5 text-[10px] font-mono text-[var(--accent-violet)] font-bold">
                                <FileText className="h-3 w-3" aria-hidden="true" />
                                <span>Document</span>
                              </span>
                            ) : record.input_type === 'screenshot' ? (
                              <span className="inline-flex items-center gap-1 rounded-md bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] font-bold">
                                <Eye className="h-3 w-3" aria-hidden="true" />
                                <span>Screenshot</span>
                              </span>
                            ) : record.input_type === 'fact_check' ? (
                              <span className="inline-flex items-center gap-1 rounded-md bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] font-bold">
                                <Globe className="h-3 w-3" aria-hidden="true" />
                                <span>Fact-Check</span>
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-md bg-[var(--surface-interactive)] border border-[var(--border)] px-2 py-0.5 text-[10px] font-mono text-[var(--foreground-secondary)] font-semibold">
                                <MessageSquare className="h-3 w-3" aria-hidden="true" />
                                <span>Message</span>
                              </span>
                            )}

                            <span
                              className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-mono font-semibold ${badge.bg}`}
                            >
                              <BadgeIcon className="h-3 w-3" aria-hidden="true" />
                              <span>{badge.label}</span>
                            </span>

                            <span className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-interactive)] px-2 py-0.5 text-[10px] font-mono text-[var(--foreground-secondary)] tabular-nums">
                              Score: {record.severity_score}/100
                            </span>

                            <span className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-interactive)] px-2 py-0.5 text-[10px] font-mono text-[var(--foreground-secondary)] capitalize">
                              Sufficiency: {record.evidence_sufficiency}
                            </span>

                            <span className="text-[11px] font-mono text-[var(--muted-foreground)] ml-auto sm:ml-0 flex items-center gap-1 tabular-nums">
                              <Calendar className="h-3 w-3" aria-hidden="true" />
                              <span>{dateStr}</span>
                            </span>
                          </div>

                          {/* Message snippet */}
                          <p className="text-xs text-[var(--foreground)] font-medium line-clamp-2 leading-relaxed">
                            &ldquo;{record.input_snippet}&rdquo;
                          </p>

                          {/* Summary */}
                          <p className="text-[11px] text-[var(--foreground-secondary)] line-clamp-1">
                            {record.summary}
                          </p>

                          {/* IOC Indicators footer */}
                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            {urlCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-1.5 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] tabular-nums">
                                {urlCount} {urlCount === 1 ? 'URL' : 'URLs'}
                              </span>
                            )}
                            {emailCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-[var(--accent-violet-subtle)] border border-[var(--accent-violet)]/30 px-1.5 py-0.5 text-[10px] font-mono text-[var(--accent-violet)] tabular-nums">
                                {emailCount} {emailCount === 1 ? 'Email' : 'Emails'}
                              </span>
                            )}
                            {phoneCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-[var(--status-success-bg)] border border-[var(--status-success-border)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--status-success)] tabular-nums">
                                {phoneCount} {phoneCount === 1 ? 'Phone' : 'Phones'}
                              </span>
                            )}
                            {record.indicators?.length > 0 && (
                              <span className="text-[10px] font-mono text-[var(--muted-foreground)] tabular-nums">
                                {record.indicators.length} warning {record.indicators.length === 1 ? 'indicator' : 'indicators'}
                              </span>
                            )}
                          </div>
                        </button>

                        {/* Actions */}
                        <div className="flex items-center gap-1.5 sm:self-center shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-[var(--border-subtle)]">
                          <button
                            type="button"
                            onClick={() => setSelectedRecord(record)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-2.5 py-1.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
                          >
                            <Eye className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
                            <span>Dossier</span>
                          </button>

                          {isConfirming ? (
                            <div className="flex items-center gap-1">
                              <button
                                type="button"
                                disabled={deletingId === record.id}
                                onClick={(e) => handleConfirmDelete(record.id, e)}
                                className="inline-flex items-center gap-1 rounded-lg border border-[var(--status-critical-border)] bg-[var(--status-critical)] px-2.5 py-1.5 text-xs font-bold text-white transition-opacity hover:opacity-90 cursor-pointer disabled:opacity-50"
                              >
                                {deletingId === record.id ? (
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                                ) : (
                                  <span>Delete</span>
                                )}
                              </button>
                              <button
                                type="button"
                                disabled={deletingId === record.id}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setConfirmDeleteId(null);
                                }}
                                className="rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-2 py-1.5 text-xs font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              disabled={deletingId === record.id}
                              onClick={(e) => {
                                e.stopPropagation();
                                setConfirmDeleteId(record.id);
                              }}
                              aria-label="Delete case file"
                              title="Delete case file"
                              className="inline-flex items-center justify-center h-8 w-8 rounded-lg border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] hover:opacity-90 text-[var(--status-critical)] transition-opacity cursor-pointer disabled:opacity-50"
                            >
                              {deletingId === record.id ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                              ) : (
                                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                              )}
                            </button>
                          )}
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </>
        )}

        {/* Case Dossier Detail Modal */}
        {selectedRecord && (
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="dossier-modal-title"
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md overflow-y-auto"
          >
            <div
              className="fixed inset-0 -z-10"
              onClick={() => setSelectedRecord(null)}
            />
            <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-8 shadow-[var(--shadow-lg)] space-y-6">
              {/* Modal Header */}
              <div className="flex items-start justify-between border-b border-[var(--border)] pb-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-[var(--accent-cyan)]">
                      CASE #{selectedRecord.id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className="text-xs text-[var(--muted-foreground)]">&middot;</span>
                    <span className="text-xs font-mono text-[var(--muted-foreground)] tabular-nums">
                      {new Date(selectedRecord.created_at).toLocaleString()}
                    </span>
                  </div>
                  <h3
                    id="dossier-modal-title"
                    className="text-lg font-bold text-[var(--foreground)] mt-1 font-[family-name:var(--font-display)]"
                  >
                    Forensic Case Dossier
                  </h3>
                </div>
                <button
                  type="button"
                  aria-label="Close dossier"
                  onClick={() => setSelectedRecord(null)}
                  className="rounded-lg p-1.5 text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)] transition-colors cursor-pointer"
                >
                  <X className="h-5 w-5" aria-hidden="true" />
                </button>
              </div>

              {/* Threat Assessment Header */}
              <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--foreground-secondary)]">Threat Severity:</span>
                    <ThreatBadge
                      level={selectedRecord.threat_severity}
                      score={selectedRecord.severity_score}
                      showScore={true}
                      size="sm"
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="text-xs font-mono text-[var(--foreground-secondary)]">
                      Confidence: <strong className="text-[var(--foreground)] capitalize">{selectedRecord.model_confidence}</strong>
                    </span>
                    {selectedRecord.evidence_sufficiency && (
                      <span className="text-xs font-mono text-[var(--foreground-secondary)]">
                        Sufficiency: <strong className="text-[var(--foreground)] capitalize">{selectedRecord.evidence_sufficiency}</strong>
                      </span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-xs text-[var(--foreground-secondary)] block font-semibold mb-1">
                    Analyst Summary:
                  </span>
                  <p className="text-xs text-[var(--foreground)] leading-relaxed">
                    {selectedRecord.summary}
                  </p>
                </div>

                {selectedRecord.confidence_rationale && (
                  <p className="text-[11px] text-[var(--muted-foreground)] italic">
                    Rationale: {selectedRecord.confidence_rationale}
                  </p>
                )}
              </div>

              {/* Original Snippet */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-semibold text-[var(--foreground)]">
                    Submitted Message Snippet:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyText(selectedRecord.input_snippet, 'snippet')}
                    className="inline-flex items-center gap-1 text-[11px] text-[var(--accent-cyan)] hover:underline cursor-pointer font-medium"
                  >
                    {copiedId === 'snippet' ? (
                      <>
                        <Check className="h-3 w-3 text-[var(--status-success)]" aria-hidden="true" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" aria-hidden="true" />
                        <span>Copy Text</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 text-xs font-mono text-[var(--foreground)] leading-relaxed break-words">
                  {selectedRecord.input_snippet}
                </div>
              </div>

              {/* Document & Visual Evidence Forensic Metadata */}
              {(selectedRecord.input_type === 'document' ||
                selectedRecord.input_type === 'screenshot' ||
                selectedRecord.iocs?.documentContent) && (
                <div className="rounded-xl border border-[var(--accent-cyan)]/30 bg-[var(--surface-interactive)] p-4 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-[var(--accent-cyan)] flex items-center gap-1.5">
                      <FileText className="h-4 w-4" aria-hidden="true" />
                      <span>Document &amp; Forensic Metadata</span>
                    </span>
                    {selectedRecord.iocs?.documentContent?.detectedType && (
                      <span className="rounded bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] capitalize">
                        {selectedRecord.iocs.documentContent.detectedType.replace('_', ' ')}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {selectedRecord.iocs?.documentContent?.filename && (
                      <div className="rounded-lg bg-[var(--background-secondary)] p-2.5 border border-[var(--border-subtle)]">
                        <span className="text-[10px] font-mono text-[var(--muted-foreground)] block">Filename:</span>
                        <span className="font-mono text-[var(--foreground)] text-[11px] truncate block">
                          {selectedRecord.iocs.documentContent.filename}
                        </span>
                      </div>
                    )}
                    {selectedRecord.iocs?.documentContent?.apparentSenderOrOrganization && (
                      <div className="rounded-lg bg-[var(--background-secondary)] p-2.5 border border-[var(--border-subtle)]">
                        <span className="text-[10px] font-mono text-[var(--muted-foreground)] block">Apparent Sender / Org:</span>
                        <span className="text-[var(--foreground)] text-[11px] truncate block">
                          {selectedRecord.iocs.documentContent.apparentSenderOrOrganization}
                        </span>
                      </div>
                    )}
                    {selectedRecord.iocs?.documentContent?.claimedPurpose && (
                      <div className="rounded-lg bg-[var(--background-secondary)] p-2.5 border border-[var(--border-subtle)] sm:col-span-2">
                        <span className="text-[10px] font-mono text-[var(--muted-foreground)] block">Claimed Purpose:</span>
                        <span className="text-[var(--foreground-secondary)] text-[11px] block">
                          {selectedRecord.iocs.documentContent.claimedPurpose}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Suspicious Elements */}
                  {selectedRecord.iocs?.suspiciousElements && selectedRecord.iocs.suspiciousElements.length > 0 && (
                    <div className="pt-2 border-t border-[var(--border-subtle)] space-y-2">
                      <span className="text-[11px] font-semibold text-[var(--foreground)] block">
                        Flagged Visual &amp; Structural Anomalies:
                      </span>
                      <div className="space-y-1.5">
                        {selectedRecord.iocs.suspiciousElements.map((elem, idx) => (
                          <div key={idx} className="rounded-lg bg-[var(--status-critical-bg)] border border-[var(--status-critical-border)] p-2.5 text-xs space-y-1">
                            <div className="flex items-center gap-1.5 text-[var(--status-critical)] font-semibold text-[11px]">
                              <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />
                              <span className="uppercase tracking-wider text-[10px]">{elem.category.replace('_', ' ')}</span>
                            </div>
                            <p className="text-[var(--foreground)] text-[11px]">{elem.explanation}</p>
                            {elem.evidence && (
                              <div className="font-mono text-[10px] text-[var(--accent-cyan)] bg-[var(--background-secondary)] px-2 py-1 rounded border border-[var(--border-subtle)]">
                                &ldquo;{elem.evidence}&rdquo;
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Unverified Claims */}
                  {selectedRecord.iocs?.verificationStatus?.unverifiedClaims && selectedRecord.iocs.verificationStatus.unverifiedClaims.length > 0 && (
                    <div className="pt-2 border-t border-[var(--border-subtle)] space-y-1.5">
                      <span className="text-[11px] font-semibold text-[var(--status-warning)] block">
                        Unverified Claims Contained in File:
                      </span>
                      <ul className="space-y-1 text-[11px] text-[var(--foreground-secondary)] list-disc list-inside">
                        {selectedRecord.iocs.verificationStatus.unverifiedClaims.map((claim, idx) => (
                          <li key={idx}>{claim}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="rounded-lg bg-[var(--status-warning-bg)] border border-[var(--status-warning-border)] p-2.5 text-[10px] text-[var(--foreground)] leading-relaxed">
                    <strong className="text-[var(--status-warning)]">Authenticity Notice:</strong> AI assessments evaluate behavioral and visual anomaly indicators. They do not cryptographically verify corporate identity or bank routing legitimacy. Always verify requests out-of-band.
                  </div>
                </div>
              )}

              {/* Web Fact-Checking Intelligence Dossier */}
              {(selectedRecord.input_type === 'fact_check' || selectedRecord.iocs?.factCheckReport) && (
                <div className="rounded-xl border border-[var(--accent-cyan)]/30 bg-[var(--surface-interactive)] p-4 space-y-3">
                  {(() => {
                    const badge = getResearchStatusBadge(selectedRecord);
                    const report = selectedRecord.iocs?.factCheckReport;
                    const hasSources = report?.sources && report.sources.length > 0;
                    const hasExtractedClaims = report?.extractedClaims && report.extractedClaims.length > 0;

                    return (
                      <>
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-[var(--accent-cyan)] flex items-center gap-1.5">
                            <Globe className="h-4 w-4" aria-hidden="true" />
                            <span>Web Fact-Checking &amp; Primary Sources</span>
                          </span>
                          <span className={`inline-flex items-center gap-1.5 rounded px-2.5 py-0.5 text-[10px] font-mono border self-start sm:self-auto ${badge.className}`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${badge.dotClass}`} aria-hidden="true" />
                            <span>{badge.label}</span>
                          </span>
                        </div>

                        {report?.searchProviderStatus && (
                          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-[var(--foreground-secondary)] bg-[var(--background-secondary)] p-2.5 rounded-lg border border-[var(--border-subtle)] tabular-nums">
                            <span>
                              Engine:{' '}
                              <strong className="text-[var(--accent-cyan)]">
                                {/serper|gemini|wikimedia|qwen|featherless/i.test(
                                  report.searchProviderStatus.providerName || report.searchProviderUsed || ''
                                )
                                  ? 'Aegis AI Research Engine'
                                  : report.searchProviderStatus.providerName || report.searchProviderUsed || 'Aegis AI Research Engine'}
                              </strong>
                            </span>
                            {report.searchProviderStatus.outboundSearchesExecuted !== undefined && (
                              <span>&middot; Outbound Queries: <strong className="text-[var(--foreground)]">{report.searchProviderStatus.outboundSearchesExecuted}</strong></span>
                            )}
                            {report.searchProviderStatus.cacheHitsCount > 0 && (
                              <span>&middot; Cached: <strong className="text-[var(--accent-cyan)]">{report.searchProviderStatus.cacheHitsCount}</strong></span>
                            )}
                          </div>
                        )}

                        {hasExtractedClaims && (
                          <div className="space-y-2">
                            <span className="text-[11px] font-semibold text-[var(--foreground)] block">
                              Verified &amp; Cross-Examined Claims:
                            </span>
                            {report.extractedClaims.map((cl: any, idx: number) => (
                              <div key={idx} className="rounded-lg bg-[var(--background-secondary)] border border-[var(--border-subtle)] p-2.5 text-xs space-y-1">
                                <div className="flex items-center justify-between gap-2">
                                  <span className="text-[var(--foreground)] text-[11px] font-medium">&ldquo;{cl.claimText}&rdquo;</span>
                                  <span
                                    className={`text-[10px] font-mono px-2 py-0.5 rounded border capitalize shrink-0 ${
                                      cl.verdict === 'contradicted'
                                        ? 'text-[var(--status-critical)] bg-[var(--status-critical-bg)] border-[var(--status-critical-border)]'
                                        : cl.verdict === 'supported'
                                        ? 'text-[var(--status-success)] bg-[var(--status-success-bg)] border-[var(--status-success-border)]'
                                        : cl.verdict === 'unverified_suspicious'
                                        ? 'text-[var(--status-uncertain)] bg-[var(--status-uncertain-bg)] border-[var(--status-uncertain-border)]'
                                        : cl.verdict === 'no_verifiable_claim'
                                        ? 'text-[var(--accent-violet)] bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30'
                                        : 'text-[var(--status-warning)] bg-[var(--status-warning-bg)] border-[var(--status-warning-border)]'
                                    }`}
                                  >
                                    {cl.verdict?.replace(/_/g, ' ')}
                                  </span>
                                </div>
                                <p className="text-[11px] text-[var(--foreground-secondary)]">{cl.verdictExplanation}</p>
                              </div>
                            ))}
                          </div>
                        )}

                        {hasSources ? (
                          <div className="pt-2 border-t border-[var(--border-subtle)] space-y-1.5">
                            <span className="text-[11px] font-semibold text-[var(--foreground)] block">
                              Referenced Public Sources &amp; Advisories:
                            </span>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                              {report.sources.map((src: any, sIdx: number) => (
                                <a
                                  key={sIdx}
                                  href={src.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="rounded-lg bg-[var(--background-secondary)] border border-[var(--border-subtle)] p-2.5 text-xs hover:border-[var(--primary-orange)]/40 transition-colors block"
                                >
                                  <div className="flex items-center justify-between text-[10px] font-mono mb-0.5">
                                    <span className="text-[var(--accent-cyan)] truncate max-w-[140px]">{src.domain}</span>
                                    <span className="text-[var(--muted-foreground)] capitalize">{src.provenance?.replace(/_/g, ' ') || 'Snippet'}</span>
                                  </div>
                                  <span className="text-[var(--foreground)] text-[11px] font-semibold line-clamp-1">{src.title}</span>
                                </a>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <div className="pt-2 border-t border-[var(--border-subtle)]">
                            <div className="rounded-lg bg-[var(--background-secondary)] border border-[var(--border-subtle)] p-2.5 text-xs text-[var(--foreground-secondary)] space-y-1">
                              <p className="font-medium text-[var(--foreground)] text-[11px]">
                                {report?.hasVerifiableClaims === false
                                  ? 'External web search was skipped because no verifiable institutional, policy, or financial assertions were identified in the submission.'
                                  : 'No external web citations were required or retrieved for this analysis.'}
                              </p>
                              {report?.claimAssessment?.assessmentReason && (
                                <p className="text-[10px] text-[var(--muted-foreground)] italic">
                                  Assessment Rationale: {report.claimAssessment.assessmentReason}
                                </p>
                              )}
                            </div>
                          </div>
                        )}
                      </>
                    );
                  })()}
                </div>
              )}

              {/* Extracted IOCs */}
              {selectedRecord.iocs && (
                <div>
                  <span className="text-xs font-semibold text-[var(--foreground)] block mb-2">
                    Extracted IOCs (Indicators of Compromise):
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {selectedRecord.iocs.urls && selectedRecord.iocs.urls.length > 0 && (
                      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-2.5 min-w-0">
                        <span className="text-[10px] font-mono text-[var(--muted-foreground)] block">Flagged URLs:</span>
                        <div className="mt-1 space-y-1">
                          {selectedRecord.iocs.urls.map((u, i) => (
                            <code key={i} className="text-[var(--accent-cyan)] text-[11px] block break-all">
                              {u}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                    {selectedRecord.iocs.emails && selectedRecord.iocs.emails.length > 0 && (
                      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-2.5 min-w-0">
                        <span className="text-[10px] font-mono text-[var(--muted-foreground)] block">Sender / Target Emails:</span>
                        <div className="mt-1 space-y-1">
                          {selectedRecord.iocs.emails.map((e, i) => (
                            <code key={i} className="text-[var(--accent-violet)] text-[11px] block break-all">
                              {e}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Warning Indicators */}
              {selectedRecord.indicators && selectedRecord.indicators.length > 0 && (
                <div>
                  <span className="text-xs font-semibold text-[var(--foreground)] block mb-2 tabular-nums">
                    Detected Threat Indicators ({selectedRecord.indicators.length}):
                  </span>
                  <div className="space-y-2">
                    {selectedRecord.indicators.map((ind, i) => (
                      <div
                        key={i}
                        className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 text-xs space-y-1.5"
                      >
                        <div className="font-semibold text-[var(--foreground)] flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 text-[var(--status-warning)] shrink-0" aria-hidden="true" />
                          <span>{ind.name}</span>
                        </div>
                        {ind.evidence && (
                          <div className="rounded bg-[var(--background-secondary)] px-2.5 py-1 font-mono text-[11px] text-[var(--accent-cyan)] border border-[var(--border-subtle)]">
                            &ldquo;{ind.evidence}&rdquo;
                          </div>
                        )}
                        <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                          {ind.reason}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              {selectedRecord.recommended_actions && selectedRecord.recommended_actions.length > 0 && (
                <div>
                  <span className="text-xs font-semibold text-[var(--foreground)] block mb-2">
                    Recommended Protective Actions:
                  </span>
                  <ul className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5 text-xs text-[var(--foreground)]">
                    {selectedRecord.recommended_actions.map((act, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 text-[var(--status-success)] shrink-0 mt-0.5" aria-hidden="true" />
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Modal Footer */}
              <div className="pt-3 border-t border-[var(--border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <span className="font-mono text-[var(--muted-foreground)] text-[11px]">
                  {selectedRecord.model_name?.includes('Bypassed') || selectedRecord.model_name?.includes('Conversational')
                    ? 'Engine: Pre-Search Rule Engine (External Search Bypassed)'
                    : 'Intelligence Engine: Aegis AI'}
                </span>
                <button
                  type="button"
                  onClick={() => setSelectedRecord(null)}
                  className="rounded-xl bg-[var(--surface)] hover:bg-[var(--surface-interactive)] border border-[var(--border)] px-4 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
                >
                  Close Dossier
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
