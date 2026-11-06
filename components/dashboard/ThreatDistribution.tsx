'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldAlert, AlertTriangle, CheckCircle2, HelpCircle, ArrowRight, ShieldCheck, ExternalLink } from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';

interface CaseItem {
  id: string;
  input_type?: string;
  input_snippet?: string;
  threat_severity?: 'high' | 'medium' | 'low' | 'uncertain' | string;
  severity_score?: number;
  summary?: string;
  created_at?: string;
}

interface ThreatDistributionProps {
  totalCases: number;
  highCount: number;
  medCount: number;
  lowCount: number;
  uncertainCount: number;
  latestHighCase?: CaseItem | null;
  isLoading: boolean;
}

export default function ThreatDistribution({
  totalCases,
  highCount,
  medCount,
  lowCount,
  uncertainCount,
  latestHighCase,
  isLoading,
}: ThreatDistributionProps) {
  const highPct = totalCases > 0 ? Math.round((highCount / totalCases) * 100) : 0;
  const medPct = totalCases > 0 ? Math.round((medCount / totalCases) * 100) : 0;
  const lowPct = totalCases > 0 ? Math.round((lowCount / totalCases) * 100) : 0;
  const uncertainPct = totalCases > 0 ? Math.max(0, 100 - highPct - medPct - lowPct) : 0;

  return (
    <section
      aria-label="Threat Severity Allocation and Priority Cases"
      className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6 shadow-sm space-y-5"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-sm sm:text-base font-bold text-[var(--foreground)] flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Threat Severity Distribution</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Empirical risk allocation derived strictly from user-submitted case dossiers.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono text-[var(--muted-foreground)]">
          <span>{totalCases} Evaluated Dossier(s)</span>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <div className="h-4 w-full bg-[var(--surface-interactive)] rounded animate-pulse" />
          <div className="h-16 w-full bg-[var(--surface-interactive)] rounded-xl animate-pulse" />
        </div>
      ) : totalCases === 0 ? (
        <div className="rounded-xl border border-dashed border-[var(--border)] bg-[var(--card-bg)] p-6 text-center space-y-2">
          <ShieldCheck className="h-8 w-8 text-[var(--muted-foreground)] mx-auto opacity-70" />
          <h4 className="text-xs sm:text-sm font-semibold text-[var(--foreground)]">
            Awaiting Initial Dossiers to Map Risk Distribution
          </h4>
          <p className="text-xs text-[var(--foreground-secondary)] max-w-md mx-auto">
            Once you analyze messages, scan documents, or screen URLs, empirical threat severity
            metrics will populate here automatically.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {/* Proportional Segmented Progress Bar */}
          <div className="space-y-2">
            <div
              className="h-3 w-full rounded-full bg-[var(--surface-interactive)] overflow-hidden flex border border-[var(--border-subtle)]"
              role="progressbar"
              aria-label="Threat Severity Breakdown"
            >
              {highCount > 0 && (
                <div
                  style={{ width: `${highPct}%` }}
                  className="bg-[var(--status-critical)] transition-all duration-300"
                  title={`High Risk: ${highCount} (${highPct}%)`}
                />
              )}
              {medCount > 0 && (
                <div
                  style={{ width: `${medPct}%` }}
                  className="bg-[var(--status-warning)] transition-all duration-300"
                  title={`Medium Risk: ${medCount} (${medPct}%)`}
                />
              )}
              {lowCount > 0 && (
                <div
                  style={{ width: `${lowPct}%` }}
                  className="bg-[var(--status-success)] transition-all duration-300"
                  title={`Low Risk: ${lowCount} (${lowPct}%)`}
                />
              )}
              {uncertainCount > 0 && (
                <div
                  style={{ width: `${uncertainPct}%` }}
                  className="bg-[var(--status-uncertain)] transition-all duration-300"
                  title={`Uncertain: ${uncertainCount} (${uncertainPct}%)`}
                />
              )}
            </div>

            {/* Unboxed Metadata Legend */}
            <div className="flex flex-wrap items-center justify-between gap-y-2 gap-x-4 text-xs font-mono pt-1 text-[var(--foreground-secondary)]">
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-[var(--status-critical)]" />
                <span className="font-semibold text-[var(--foreground)]">High:</span>
                <span>{highCount} ({highPct}%)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-[var(--status-warning)]" />
                <span className="font-semibold text-[var(--foreground)]">Medium:</span>
                <span>{medCount} ({medPct}%)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-[var(--status-success)]" />
                <span className="font-semibold text-[var(--foreground)]">Low:</span>
                <span>{lowCount} ({lowPct}%)</span>
              </div>
              {uncertainCount > 0 && (
                <div className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-[var(--status-uncertain)]" />
                  <span className="font-semibold text-[var(--foreground)]">Uncertain:</span>
                  <span>{uncertainCount} ({uncertainPct}%)</span>
                </div>
              )}
            </div>
          </div>

          {/* High Priority Highlight Card */}
          {latestHighCase ? (
            <div className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] uppercase font-bold text-[var(--status-critical)] px-2 py-0.5 rounded border border-[var(--status-critical-border)] bg-[var(--surface)]">
                    Priority Case Spotlight
                  </span>
                  <span className="text-xs font-mono text-[var(--foreground)] font-semibold truncate">
                    &ldquo;{latestHighCase.input_snippet}&rdquo;
                  </span>
                </div>
                <p className="text-xs text-[var(--foreground-secondary)] line-clamp-1">
                  {latestHighCase.summary || 'Immediate review recommended to contain social engineering exposure.'}
                </p>
              </div>

              <Link
                href="/investigations"
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--status-critical)] text-white px-3 py-1.5 text-xs font-semibold shrink-0 hover:opacity-95 transition-opacity"
              >
                <span>Inspect in Vault</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] px-4 py-3 text-xs text-[var(--foreground-secondary)] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-[var(--status-success)]" />
                <span>Zero uncontained high-risk threats detected in recent triage events.</span>
              </div>
              <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Clean Baseline</span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
