'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
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
  ArrowRight,
  Database,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  Eye,
  X,
  RefreshCw,
  Loader2,
  Calendar,
  Cpu,
  Download,
  CheckCircle2,
  LogIn,
  UserPlus,
  FileText,
  AlertCircle,
  Copy,
  Check,
} from 'lucide-react';

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
  };
  created_at: string;
}

export default function InvestigationsPage() {
  const { user, profile, loading: authLoading, authState } = useAuth();
  const [records, setRecords] = useState<AnalysisHistoryRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState<boolean>(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AnalysisHistoryRecord | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const supabase = useMemo(() => createClient(), []);

  // Event handler for explicit manual refresh button
  const handleManualRefresh = useCallback(async () => {
    if (!user) return;
    setLoadingRecords(true);
    setFetchError(null);
    try {
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

  useEffect(() => {
    if (authLoading || !user) {
      return;
    }

    let isMounted = true;
    const fetchCases = async () => {
      try {
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

  const handleDeleteRecord = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this investigation record? This action cannot be undone.')) {
      return;
    }

    setDeletingId(id);
    try {
      const { error } = await supabase
        .from('analysis_history')
        .delete()
        .eq('id', id);

      if (error) {
        alert(`Failed to delete record: ${error.message}`);
      } else {
        setRecords((prev) => prev.filter((r) => r.id !== id));
        if (selectedRecord?.id === id) {
          setSelectedRecord(null);
        }
      }
    } catch (err: any) {
      alert(`Deletion error: ${err.message}`);
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
      return matchesSeverity && matchesSearch;
    });
  }, [records, searchQuery, selectedSeverity]);

  // Summary statistics
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
          bg: 'bg-red-500/10 text-red-400 border-red-500/30',
          dot: 'bg-red-400',
          icon: AlertOctagon,
        };
      case 'medium':
        return {
          label: 'Medium Risk',
          bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          dot: 'bg-amber-400',
          icon: AlertTriangle,
        };
      case 'low':
        return {
          label: 'Low / Safe',
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-400',
          icon: ShieldCheck,
        };
      default:
        return {
          label: 'Uncertain',
          bg: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
          dot: 'bg-purple-400',
          icon: ShieldQuestion,
        };
    }
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Module Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400 mb-2">
            <span>Case Intelligence &middot; Personal Forensic Vault</span>
          </div>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
                <SearchCode className="h-7 w-7 text-cyan-400" />
                <span>Threat Investigations</span>
              </h2>
              <p className="mt-1 text-xs sm:text-sm text-slate-400">
                User-isolated case management, extracted Indicators of Compromise (IOCs), and forensic timelines.
              </p>
            </div>

            {user && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleManualRefresh}
                  disabled={loadingRecords}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${loadingRecords ? 'animate-spin' : ''}`} />
                  <span>Refresh Cases</span>
                </button>
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-white shadow-md shadow-cyan-600/30 transition-colors"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>New Analysis</span>
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Initial Session Verification State */}
        {authState === 'loading' && (
          <div className="rounded-2xl border border-white/5 bg-[#0d1322]/60 p-12 text-center max-w-2xl mx-auto space-y-4">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Verifying Secure Analyst Session</h3>
              <p className="text-xs text-slate-400 mt-1">
                Confirming credentials and checking encrypted database permissions...
              </p>
            </div>
          </div>
        )}

        {/* Unauthenticated State */}
        {authState === 'unauthenticated' && !user && (
          <div className="rounded-2xl border border-cyan-500/20 bg-[#0d1322]/90 p-8 sm:p-10 shadow-2xl text-center max-w-2xl mx-auto space-y-6">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
              <Lock className="h-7 w-7" />
            </div>

            <div>
              <h3 className="text-xl font-bold text-white">
                Private Investigation Vault
              </h3>
              <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
                You are currently exploring in <strong className="text-white">Guest Mode</strong> with zero-retention ephemeral memory. To retain persistent case histories, track IOC timelines, and unlock collaborative investigations across devices, sign in to your verified analyst workspace.
              </p>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 text-xs text-slate-400 text-left space-y-2">
              <div className="flex items-center gap-2 text-slate-300 font-semibold">
                <Database className="h-4 w-4 text-cyan-400" />
                <span>Zero-Trust Database Isolation:</span>
              </div>
              <p className="text-[11px] leading-relaxed">
                All saved investigation records are bound strictly to your authenticated UUID and protected with PostgreSQL Row Level Security (RLS). No other user or guest can query your private case logs.
              </p>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/auth/login?next=/investigations"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-5 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer"
              >
                <LogIn className="h-4 w-4" />
                <span>Sign In to Access Vault</span>
              </Link>
              <Link
                href="/auth/register"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-5 py-2.5 text-xs font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                <UserPlus className="h-4 w-4 text-cyan-400" />
                <span>Create Analyst Account</span>
              </Link>
            </div>
          </div>
        )}

        {/* Authenticated State */}
        {user && (
          <>
            {/* Case Metrics Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
              <div className="rounded-xl border border-white/5 bg-[#0d1322] p-3.5">
                <span className="text-[11px] font-mono text-slate-500 block">Total Cases</span>
                <span className="text-xl font-bold text-white mt-1 block">{stats.total}</span>
              </div>
              <div className="rounded-xl border border-red-500/20 bg-red-950/20 p-3.5">
                <span className="text-[11px] font-mono text-red-400 block">High Threat</span>
                <span className="text-xl font-bold text-red-300 mt-1 block">{stats.high}</span>
              </div>
              <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-3.5">
                <span className="text-[11px] font-mono text-amber-400 block">Medium Risk</span>
                <span className="text-xl font-bold text-amber-300 mt-1 block">{stats.medium}</span>
              </div>
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3.5">
                <span className="text-[11px] font-mono text-emerald-400 block">Safe / Low</span>
                <span className="text-xl font-bold text-emerald-300 mt-1 block">{stats.low}</span>
              </div>
              <div className="rounded-xl border border-purple-500/20 bg-purple-950/20 p-3.5">
                <span className="text-[11px] font-mono text-purple-400 block">Uncertain</span>
                <span className="text-xl font-bold text-purple-300 mt-1 block">{stats.uncertain}</span>
              </div>
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-3.5">
                <span className="text-[11px] font-mono text-cyan-400 block">Avg Severity</span>
                <span className="text-xl font-bold text-cyan-300 mt-1 block">{stats.avgScore}/100</span>
              </div>
            </div>

            {/* Filter and Search Controls */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-white/5 bg-[#0d1322] p-3">
              <div className="relative w-full sm:w-80">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by keyword, URL, or IOC..."
                  className="w-full rounded-lg border border-white/10 bg-[#090d18] pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
                {['all', 'high', 'medium', 'low', 'uncertain'].map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSelectedSeverity(sev)}
                    className={`rounded-lg px-2.5 py-1 text-xs font-medium capitalize transition-colors cursor-pointer shrink-0 ${
                      selectedSeverity === sev
                        ? 'bg-cyan-600 text-white font-semibold'
                        : 'text-slate-400 hover:text-white hover:bg-slate-900'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {/* Error Message */}
            {fetchError && (
              <div
                role="alert"
                className="rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-xs text-red-300 flex items-start gap-2.5"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                <div className="flex-1">
                  <strong>Failed to query investigation history:</strong>
                  <p className="mt-1">{fetchError}</p>
                </div>
              </div>
            )}

            {/* Loading Skeleton */}
            {loadingRecords && (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className="h-28 rounded-2xl border border-white/5 bg-[#0d1322] p-4 animate-pulse flex flex-col justify-between"
                  >
                    <div className="h-4 bg-slate-800 rounded w-1/3" />
                    <div className="h-3 bg-slate-800 rounded w-3/4" />
                    <div className="h-3 bg-slate-800 rounded w-1/4" />
                  </div>
                ))}
              </div>
            )}

            {/* Empty State */}
            {!loadingRecords && filteredRecords.length === 0 && (
              <div className="rounded-2xl border border-dashed border-white/10 bg-[#0d1322]/50 p-12 text-center space-y-4">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 border border-white/10 text-slate-400">
                  <SearchCode className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    {searchQuery || selectedSeverity !== 'all'
                      ? 'No matching investigation records'
                      : 'No investigation records yet'}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                    {searchQuery || selectedSeverity !== 'all'
                      ? 'Try adjusting your search terms or filter settings.'
                      : 'Messages analyzed while authenticated are automatically recorded in this private vault.'}
                  </p>
                </div>
                <div>
                  <Link
                    href="/analyze"
                    className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-xs font-semibold text-white transition-colors"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
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

                  return (
                    <div
                      key={record.id}
                      onClick={() => setSelectedRecord(record)}
                      className="group rounded-2xl border border-white/5 bg-[#0d1322] hover:border-cyan-500/30 p-4 sm:p-5 transition-all cursor-pointer shadow-lg hover:shadow-cyan-950/30"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                        <div className="space-y-2 flex-1 min-w-0">
                          {/* Badges line */}
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-mono font-semibold ${badge.bg}`}
                            >
                              <BadgeIcon className="h-3 w-3" />
                              <span>{badge.label}</span>
                            </span>

                            <span className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-mono text-slate-400">
                              Score: {record.severity_score}/100
                            </span>

                            <span className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-mono text-slate-400">
                              Sufficiency: {record.evidence_sufficiency}
                            </span>

                            <span className="text-[11px] font-mono text-slate-500 ml-auto sm:ml-0 flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              <span>{dateStr}</span>
                            </span>
                          </div>

                          {/* Message snippet */}
                          <p className="text-xs text-slate-200 font-medium line-clamp-2 leading-relaxed">
                            &ldquo;{record.input_snippet}&rdquo;
                          </p>

                          {/* Summary */}
                          <p className="text-[11px] text-slate-400 line-clamp-1">
                            {record.summary}
                          </p>

                          {/* IOC Indicators footer */}
                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            {urlCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-blue-950/60 border border-blue-500/30 px-1.5 py-0.5 text-[10px] font-mono text-blue-300">
                                🔗 {urlCount} {urlCount === 1 ? 'URL' : 'URLs'}
                              </span>
                            )}
                            {emailCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-indigo-950/60 border border-indigo-500/30 px-1.5 py-0.5 text-[10px] font-mono text-indigo-300">
                                ✉️ {emailCount} {emailCount === 1 ? 'Email' : 'Emails'}
                              </span>
                            )}
                            {phoneCount > 0 && (
                              <span className="inline-flex items-center gap-1 rounded bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-mono text-emerald-300">
                                📞 {phoneCount} {phoneCount === 1 ? 'Phone' : 'Phones'}
                              </span>
                            )}
                            {record.indicators?.length > 0 && (
                              <span className="text-[10px] font-mono text-slate-500">
                                {record.indicators.length} warning {record.indicators.length === 1 ? 'indicator' : 'indicators'}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-1.5 sm:self-center shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-white/5">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedRecord(record);
                            }}
                            className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors cursor-pointer"
                          >
                            <Eye className="h-3.5 w-3.5 text-cyan-400" />
                            <span>Dossier</span>
                          </button>

                          <button
                            type="button"
                            disabled={deletingId === record.id}
                            onClick={(e) => handleDeleteRecord(record.id, e)}
                            title="Delete case file"
                            className="inline-flex items-center justify-center h-8 w-8 rounded-lg border border-red-500/20 bg-red-950/20 hover:bg-red-950/50 text-red-400 hover:text-red-300 transition-colors cursor-pointer disabled:opacity-50"
                          >
                            {deletingId === record.id ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <Trash2 className="h-3.5 w-3.5" />
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}

        {/* Case Dossier Detail Modal */}
        {selectedRecord && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md overflow-y-auto">
            <div
              className="fixed inset-0 -z-10"
              onClick={() => setSelectedRecord(null)}
            />
            <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-white/15 bg-[#0d1322] p-6 sm:p-8 shadow-2xl space-y-6">
              {/* Modal Header */}
              <div className="flex items-start justify-between border-b border-white/10 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-cyan-400">
                      CASE #{selectedRecord.id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-500">&middot;</span>
                    <span className="text-xs font-mono text-slate-400">
                      {new Date(selectedRecord.created_at).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white mt-1">
                    Forensic Case Dossier
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedRecord(null)}
                  className="rounded-lg p-1.5 text-slate-400 hover:text-white hover:bg-slate-900 transition-colors cursor-pointer"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Threat Assessment Header */}
              <div className="rounded-xl border border-white/10 bg-[#090d18] p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Threat Severity:</span>
                    <span
                      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-mono font-bold uppercase ${
                        getSeverityBadge(selectedRecord.threat_severity).bg
                      }`}
                    >
                      {selectedRecord.threat_severity}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: <strong className="text-white capitalize">{selectedRecord.model_confidence}</strong>
                  </span>
                </div>

                <div>
                  <span className="text-xs text-slate-400 block font-semibold mb-1">
                    Analyst Summary:
                  </span>
                  <p className="text-xs text-slate-200 leading-relaxed">
                    {selectedRecord.summary}
                  </p>
                </div>

                {selectedRecord.confidence_rationale && (
                  <p className="text-[11px] text-slate-400 italic">
                    Rationale: {selectedRecord.confidence_rationale}
                  </p>
                )}
              </div>

              {/* Original Snippet */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-semibold text-slate-300">
                    Submitted Message Snippet:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyText(selectedRecord.input_snippet, 'snippet')}
                    className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedId === 'snippet' ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy Text</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="rounded-xl border border-white/5 bg-[#090d18] p-3 text-xs font-mono text-slate-300 leading-relaxed break-words">
                  {selectedRecord.input_snippet}
                </div>
              </div>

              {/* Extracted IOCs */}
              {selectedRecord.iocs && (
                <div>
                  <span className="text-xs font-semibold text-slate-300 block mb-2">
                    Extracted IOCs (Indicators of Compromise):
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {selectedRecord.iocs.urls && selectedRecord.iocs.urls.length > 0 && (
                      <div className="rounded-lg border border-white/5 bg-[#090d18] p-2.5">
                        <span className="text-[10px] font-mono text-slate-500 block">Flagged URLs:</span>
                        <div className="mt-1 space-y-1">
                          {selectedRecord.iocs.urls.map((u, i) => (
                            <code key={i} className="text-blue-400 text-[11px] block truncate">
                              {u}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                    {selectedRecord.iocs.emails && selectedRecord.iocs.emails.length > 0 && (
                      <div className="rounded-lg border border-white/5 bg-[#090d18] p-2.5">
                        <span className="text-[10px] font-mono text-slate-500 block">Sender / Target Emails:</span>
                        <div className="mt-1 space-y-1">
                          {selectedRecord.iocs.emails.map((e, i) => (
                            <code key={i} className="text-indigo-400 text-[11px] block truncate">
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
                  <span className="text-xs font-semibold text-slate-300 block mb-2">
                    Detected Threat Indicators ({selectedRecord.indicators.length}):
                  </span>
                  <div className="space-y-2">
                    {selectedRecord.indicators.map((ind, i) => (
                      <div
                        key={i}
                        className="rounded-xl border border-white/5 bg-[#090d18] p-3 text-xs space-y-1.5"
                      >
                        <div className="font-semibold text-white flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                          <span>{ind.name}</span>
                        </div>
                        {ind.evidence && (
                          <div className="rounded bg-black/40 px-2 py-1 font-mono text-[11px] text-cyan-300 border border-white/5">
                            &ldquo;{ind.evidence}&rdquo;
                          </div>
                        )}
                        <p className="text-[11px] text-slate-400 leading-relaxed">
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
                  <span className="text-xs font-semibold text-slate-300 block mb-2">
                    Recommended Protective Actions:
                  </span>
                  <ul className="rounded-xl border border-white/5 bg-[#090d18] p-3 space-y-1.5 text-xs text-slate-300">
                    {selectedRecord.recommended_actions.map((act, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Modal Footer */}
              <div className="pt-2 border-t border-white/5 flex items-center justify-between text-xs">
                <span className="font-mono text-slate-500 text-[11px]">
                  Model: {selectedRecord.model_name || 'Qwen/Qwen3-VL-8B-Instruct'}
                </span>
                <button
                  type="button"
                  onClick={() => setSelectedRecord(null)}
                  className="rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/10 px-4 py-2 text-xs font-medium text-white transition-colors cursor-pointer"
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
