'use client';

import React from 'react';
import { Binary, ShieldAlert, CheckCircle2, AlertTriangle, Info, Clock, Tag } from 'lucide-react';
import { ThreatIntelRecord } from '@/lib/fact-checker/types';

interface UrlhausCardProps {
  threatIntel: ThreatIntelRecord[];
}

export default function UrlhausCard({ threatIntel }: UrlhausCardProps) {
  return (
    <section
      aria-label="URLhaus Threat Intelligence Feed Attribution"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <Binary className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Exact Threat-Feed Attribution (URLhaus)</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Cryptographic indicator matching, queried vs matched targets, and API telemetry.
          </p>
        </div>
        <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
          abuse.ch Registry
        </span>
      </div>

      {threatIntel && threatIntel.length > 0 ? (
        <div className="space-y-3">
          {threatIntel.map((intel, idx) => {
            const isItemMalicious = intel.status === 'malicious';

            return (
              <div
                key={idx}
                className={`rounded-xl border p-4 space-y-3 text-xs font-mono transition-colors ${
                  isItemMalicious
                    ? 'border-[var(--status-critical)]/40 bg-[var(--status-critical-bg)]'
                    : 'border-[var(--border-subtle)] bg-[var(--surface-interactive)]'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-subtle)] pb-2.5">
                  <div className="flex items-center gap-2 min-w-0">
                    {isItemMalicious ? (
                      <ShieldAlert className="h-4 w-4 text-[var(--status-critical)] shrink-0" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-[var(--status-success)] shrink-0" />
                    )}
                    <span className="font-bold text-[var(--foreground)] truncate max-w-[240px] sm:max-w-[320px]">
                      Provider: {intel.provider}
                    </span>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                      isItemMalicious
                        ? 'bg-[var(--status-critical)] text-white'
                        : 'bg-[var(--status-success-bg)] text-[var(--status-success)] border border-[var(--status-success-border)]'
                    }`}
                  >
                    {isItemMalicious ? 'KNOWN MALICIOUS' : 'NOT LISTED IN FEED'}
                  </span>
                </div>

                {/* Attribution Breakdown Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] bg-[var(--background)] p-3 rounded-lg border border-[var(--border-subtle)]">
                  <div>
                    <span className="text-[var(--muted-foreground)] block">Queried Indicator:</span>
                    <span className="text-[var(--foreground)] font-bold truncate block" title={intel.queriedIndicator || intel.indicator}>
                      {intel.queriedIndicator || intel.indicator}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted-foreground)] block">Matched Indicator:</span>
                    <span className="text-[var(--foreground)] font-bold truncate block" title={intel.matchedIndicator || 'None'}>
                      {intel.matchedIndicator || 'None'}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted-foreground)] block">Match Type:</span>
                    <span className="text-[var(--primary-orange)] font-bold uppercase">
                      {intel.matchType || 'no_match'}
                    </span>
                  </div>

                  <div>
                    <span className="text-[var(--muted-foreground)] block">Provider Status:</span>
                    <span className="text-[var(--foreground)] font-bold">
                      {intel.providerResponseStatus || intel.status}
                    </span>
                  </div>
                </div>

                {intel.threatType && (
                  <div className="text-[var(--foreground-secondary)] text-[11px]">
                    <span className="text-[var(--muted-foreground)]">Threat Classification:</span>{' '}
                    <strong className="text-[var(--foreground)]">{intel.threatType}</strong>
                  </div>
                )}

                {intel.tags && intel.tags.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] text-[var(--muted-foreground)]">Tags:</span>
                    {intel.tags.map((t, tid) => (
                      <span
                        key={tid}
                        className="rounded bg-[var(--background)] px-1.5 py-0.5 text-[10px] border border-[var(--border)] text-[var(--foreground-secondary)]"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>
                )}

                {intel.details && (
                  <p className="text-xs font-sans text-[var(--foreground-secondary)] leading-relaxed">
                    {intel.details}
                  </p>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[var(--border-subtle)] text-[10px] text-[var(--muted-foreground)] font-mono">
                  <span>Retrieved: {new Date(intel.retrievedAt).toLocaleTimeString()}</span>
                  {intel.dateAdded && <span>Cataloged: {intel.dateAdded}</span>}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 text-center space-y-1">
          <p className="text-xs text-[var(--foreground-secondary)]">
            No matching indicators cataloged in active URLhaus malware databases.
          </p>
        </div>
      )}

      {/* Authoritative Threat Intelligence Invariant Banner */}
      <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] p-3 text-[11px] text-[var(--muted-foreground)] flex items-start gap-2.5">
        <Info className="h-4 w-4 text-[var(--primary-orange)] shrink-0 mt-0.5" />
        <span className="leading-tight">
          <strong className="text-[var(--foreground)]">Not Listed &ne; Safe:</strong> URLhaus focuses on active malware distribution sites and botnet C2 payloads. Targeted spearphishing forms, brand impersonation portals, and newly registered malicious links routinely evade community blocklists.
        </span>
      </div>
    </section>
  );
}
