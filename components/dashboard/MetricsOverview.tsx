'use client';

import React from 'react';
import { Database, ShieldAlert, Clock, GraduationCap, ArrowUpRight } from 'lucide-react';
import Link from 'next/link';

interface MetricsOverviewProps {
  isAuthenticated: boolean;
  savedCount: number | null;
  sessionCount: number;
  highRiskCount: number;
  medRiskCount: number;
  lowRiskCount: number;
  lastActivityTimestamp?: string;
  verifiedAcademyCount: number;
  isLoading: boolean;
  formatRelativeTime: (dateString?: string) => string;
  formatCaseDate: (dateString?: string) => string;
}

export default function MetricsOverview({
  isAuthenticated,
  savedCount,
  sessionCount,
  highRiskCount,
  medRiskCount,
  lowRiskCount,
  lastActivityTimestamp,
  verifiedAcademyCount,
  isLoading,
  formatRelativeTime,
  formatCaseDate,
}: MetricsOverviewProps) {
  const totalCount = isAuthenticated ? (savedCount ?? 0) : sessionCount;

  return (
    <section aria-label="Intelligence Metrics Overview" className="space-y-3.5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
        <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-[var(--primary-orange)]" />
          <span>Operational Intelligence Posture</span>
        </h2>
        <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--muted-foreground)]">
          <span>{isAuthenticated ? 'Cloud Vault Storage' : 'Local RAM Session'}</span>
          <span aria-hidden="true">&middot;</span>
          <span>Zero Fabricated Telemetry</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Total Investigations */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 flex flex-col justify-between shadow-sm transition-all duration-200 hover:border-[var(--primary-orange)]/30 hover:shadow-md">
          <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
            <span className="font-medium tracking-wide">Total Dossiers</span>
            <div className="h-8 w-8 rounded-lg bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] flex items-center justify-center">
              <Database className="h-4 w-4" />
            </div>
          </div>

          <div className="my-3.5">
            {isLoading ? (
              <div className="h-8 w-20 bg-[var(--surface-interactive)] rounded animate-pulse" />
            ) : (
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-3xl font-extrabold text-[var(--foreground)] tabular-nums">
                  {totalCount}
                </span>
                <span className="text-xs font-mono text-[var(--muted-foreground)]">
                  {isAuthenticated ? 'in Cloud Vault' : 'in Session RAM'}
                </span>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--foreground-secondary)]">
            <span>{isAuthenticated ? 'PostgreSQL RLS Active' : 'Volatile Browser Memory'}</span>
            <Link
              href="/investigations"
              className="text-[var(--primary-orange)] hover:underline inline-flex items-center gap-0.5"
            >
              <span>Vault</span>
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
        </div>

        {/* Metric 2: High-Risk Cases */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 flex flex-col justify-between shadow-sm transition-all duration-200 hover:border-[var(--status-critical)]/30 hover:shadow-md">
          <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
            <span className="font-medium tracking-wide">High-Risk Cases</span>
            <div className="h-8 w-8 rounded-lg bg-[var(--status-critical-bg)] text-[var(--status-critical)] flex items-center justify-center">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>

          <div className="my-3.5">
            {isLoading ? (
              <div className="h-8 w-24 bg-[var(--surface-interactive)] rounded animate-pulse" />
            ) : (
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-3xl font-extrabold text-[var(--status-critical)] tabular-nums">
                  {highRiskCount}
                </span>
                <span className="text-xs font-mono text-[var(--muted-foreground)]">
                  High-Severity Findings
                </span>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--foreground-secondary)]">
            <span>
              {highRiskCount > 0
                ? `${highRiskCount} high-severity case(s) logged`
                : 'No high-risk cases recorded'}
            </span>
            <span className="text-[var(--muted-foreground)]">{medRiskCount} Med &middot; {lowRiskCount} Low</span>
          </div>
        </div>

        {/* Metric 3: Recent Activity Event */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 flex flex-col justify-between shadow-sm transition-all duration-200 hover:border-[var(--accent-cyan)]/30 hover:shadow-md">
          <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
            <span className="font-medium tracking-wide">Recent Triage Event</span>
            <div className="h-8 w-8 rounded-lg bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)] flex items-center justify-center">
              <Clock className="h-4 w-4" />
            </div>
          </div>

          <div className="my-3.5">
            {isLoading ? (
              <div className="h-8 w-28 bg-[var(--surface-interactive)] rounded animate-pulse" />
            ) : (
              <div className="truncate">
                <span className="font-mono text-xl sm:text-2xl font-bold text-[var(--foreground)] truncate block">
                  {lastActivityTimestamp ? formatRelativeTime(lastActivityTimestamp) : 'Awaiting Event'}
                </span>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--foreground-secondary)] truncate">
            <span className="truncate">
              {lastActivityTimestamp
                ? `Logged ${formatCaseDate(lastActivityTimestamp)}`
                : 'Run an analysis to record'}
            </span>
            <span className="text-[var(--accent-cyan)] text-[10px] uppercase font-bold shrink-0">Live</span>
          </div>
        </div>

        {/* Metric 4: Cybersecurity Academy Progress */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 flex flex-col justify-between shadow-sm transition-all duration-200 hover:border-[var(--accent-violet)]/30 hover:shadow-md">
          <div className="flex items-center justify-between text-xs text-[var(--muted-foreground)]">
            <span className="font-medium tracking-wide">Academy Mastery</span>
            <div className="h-8 w-8 rounded-lg bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)] flex items-center justify-center">
              <GraduationCap className="h-4 w-4" />
            </div>
          </div>

          <div className="my-3.5">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-3xl font-extrabold text-[var(--accent-violet)] tabular-nums">
                {verifiedAcademyCount}
              </span>
              <span className="text-xs font-mono text-[var(--muted-foreground)]">
                / 4 Modules Verified
              </span>
            </div>
          </div>

          <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--foreground-secondary)]">
            <span>
              {verifiedAcademyCount === 4
                ? 'Curriculum Completed'
                : `${4 - verifiedAcademyCount} module(s) open`}
            </span>
            <Link
              href="/academy"
              className="text-[var(--accent-violet)] hover:underline inline-flex items-center gap-0.5"
            >
              <span>Train</span>
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
