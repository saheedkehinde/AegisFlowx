'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Database,
  Clock,
  RefreshCw,
  ArrowRight,
  ShieldAlert,
  FileText,
  LogIn,
  UserPlus,
  Trash2,
  Filter,
} from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';
import type { SessionAnalysisRecord } from '@/lib/session-store';

export interface SavedCaseSummary {
  id: string;
  input_type: string;
  input_snippet: string;
  threat_severity: 'high' | 'medium' | 'low' | 'uncertain';
  severity_score: number;
  summary: string;
  created_at: string;
}

interface RecentInvestigationsProps {
  isAuthenticated: boolean;
  userEmail?: string;
  displayName?: string;
  savedCases: SavedCaseSummary[];
  savedCount: number | null;
  sessionAnalyses: SessionAnalysisRecord[];
  loadingCases: boolean;
  casesError: string | null;
  onRefresh: () => void;
  onClearSession: () => void;
  formatCaseDate: (dateString?: string) => string;
}

export default function RecentInvestigations({
  isAuthenticated,
  userEmail,
  displayName,
  savedCases,
  savedCount,
  sessionAnalyses,
  loadingCases,
  casesError,
  onRefresh,
  onClearSession,
  formatCaseDate,
}: RecentInvestigationsProps) {
  const [filterType, setFilterType] = useState<string>('all');

  // Explicitly ensure newest cases are ordered first
  const sortedAuthCases = [...savedCases].sort((a, b) => {
    const tA = new Date(a.created_at).getTime();
    const tB = new Date(b.created_at).getTime();
    if (isNaN(tA) || isNaN(tB)) return 0;
    return tB - tA;
  });

  // Filter cases based on selected tab
  const filteredAuthCases = sortedAuthCases.filter((item) => {
    if (filterType === 'all') return true;
    if (filterType === 'high') return item.threat_severity === 'high';
    if (filterType === 'url') return item.input_type?.includes('url');
    if (filterType === 'message') return item.input_type?.includes('message') || !item.input_type;
    if (filterType === 'document') return item.input_type?.includes('document');
    return true;
  });

  const filteredSessionCases = sessionAnalyses.filter((item) => {
    if (filterType === 'all') return true;
    if (filterType === 'high') return item.riskLevel === 'high';
    if (filterType === 'url') return item.snippet.startsWith('[URL]');
    if (filterType === 'message') return !item.snippet.startsWith('[URL]');
    return true;
  });

  return (
    <div className="space-y-4">
      {isAuthenticated ? (
        /* ================= AUTHENTICATED VAULT ================= */
        <section aria-label="Saved Cloud Investigations" className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
                <Database className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>
                  Recent Investigation Dossiers {savedCount !== null ? `(${savedCount} in Vault)` : ''}
                </span>
              </h2>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Investigation history for{' '}
                <strong className="text-[var(--foreground)]">{displayName || userEmail}</strong>,
                secured with PostgreSQL Row Level Security.
              </p>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto">
              <button
                type="button"
                onClick={onRefresh}
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

          {/* Quick Segmented Filter */}
          {savedCases.length > 0 && (
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
              <button
                type="button"
                onClick={() => setFilterType('all')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  filterType === 'all'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                    : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                All Dossiers ({savedCases.length})
              </button>
              <button
                type="button"
                onClick={() => setFilterType('high')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  filterType === 'high'
                    ? 'bg-[var(--status-critical)] text-white'
                    : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                Critical Threats
              </button>
              <button
                type="button"
                onClick={() => setFilterType('url')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  filterType === 'url'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                    : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                URLs
              </button>
              <button
                type="button"
                onClick={() => setFilterType('message')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  filterType === 'message'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                    : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                Messages
              </button>
            </div>
          )}

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
                onClick={onRefresh}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--status-critical)] text-white px-3.5 py-1.5 font-semibold text-xs transition-colors shrink-0 cursor-pointer"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Retry Query</span>
              </button>
            </div>
          ) : filteredAuthCases.length > 0 ? (
            <div className="space-y-3">
              {filteredAuthCases.map((item) => (
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
                  {filterType === 'all'
                    ? 'Your Private Investigation Vault is Empty'
                    : 'No Dossiers Match This Filter'}
                </h4>
                <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                  Analyses conducted while authenticated are automatically secured with row-level
                  security isolation. Submit your first suspicious message or upload a document to initialize
                  your vault.
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
        /* ================= GUEST VOLATILE MEMORY ================= */
        <section aria-label="Session Analyses" className="space-y-4">
          {/* Guest notice and persistent storage CTA */}
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
            <div className="space-y-1 max-w-xl">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] text-[var(--status-warning)]">
                  Volatile Memory
                </span>
                <h4 className="text-sm sm:text-base font-bold text-[var(--foreground)]">
                  Analyses buffered in temporary session RAM
                </h4>
              </div>
              <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                Submissions are held locally in volatile browser storage and will be cleared when your tab
                closes. Sign in to automatically archive cases to your private, RLS-protected cloud vault.
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
                  onClick={onClearSession}
                  className="text-[11px] font-mono text-[var(--muted-foreground)] hover:text-[var(--status-critical)] transition-colors cursor-pointer inline-flex items-center gap-1"
                >
                  <Trash2 className="h-3 w-3" />
                  <span>Clear session memory</span>
                </button>
              )}
            </div>

            {/* Guest Segmented Filter */}
            {sessionAnalyses.length > 0 && (
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
                <button
                  type="button"
                  onClick={() => setFilterType('all')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    filterType === 'all'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                      : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  All ({sessionAnalyses.length})
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('high')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    filterType === 'high'
                      ? 'bg-[var(--status-critical)] text-white'
                      : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  Critical Threats
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('url')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    filterType === 'url'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                      : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  URLs
                </button>
                <button
                  type="button"
                  onClick={() => setFilterType('message')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    filterType === 'message'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                      : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  Messages
                </button>
              </div>
            )}

            {filteredSessionCases.length > 0 ? (
              <div className="space-y-3">
                {filteredSessionCases.map((item) => (
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
                  Submit any suspicious SMS text, unexpected executive wire request, or unfamiliar URL
                  in the AI Analyzer to inspect behavioral threat indicators.
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
    </div>
  );
}
