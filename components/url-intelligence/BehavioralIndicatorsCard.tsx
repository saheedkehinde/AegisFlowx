'use client';

import React, { useState } from 'react';
import { ShieldCheck, AlertTriangle, AlertOctagon, Info, ChevronRight, Copy, Check } from 'lucide-react';
import { UrlIndicatorItem } from '@/lib/url-investigation/types';

interface BehavioralIndicatorsCardProps {
  indicators: UrlIndicatorItem[];
}

export default function BehavioralIndicatorsCard({ indicators }: BehavioralIndicatorsCardProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const categories = [
    { key: 'all', label: 'All Findings', count: indicators.length },
    { key: 'protocol', label: 'Protocol', count: indicators.filter((i) => i.category === 'protocol').length },
    { key: 'hostname', label: 'Hostname', count: indicators.filter((i) => i.category === 'hostname').length },
    { key: 'path_or_query', label: 'Path / Query', count: indicators.filter((i) => i.category === 'path_or_query').length },
    { key: 'infrastructure', label: 'Infrastructure', count: indicators.filter((i) => i.category === 'infrastructure').length },
    { key: 'reputation', label: 'Reputation', count: indicators.filter((i) => i.category === 'reputation').length },
  ].filter((c) => c.key === 'all' || c.count > 0);

  const filteredIndicators =
    selectedCategory === 'all'
      ? indicators
      : indicators.filter((i) => i.category === selectedCategory);

  const highSeverityCount = indicators.filter((i) => i.severity === 'high').length;
  const mediumSeverityCount = indicators.filter((i) => i.severity === 'medium').length;

  return (
    <section
      aria-label="Behavioral and Structural Risk Indicators"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Behavioral &amp; Structural Anomaly Analysis</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Heuristic detection for credential harvesting, misleading paths, homoglyphs, and evasive patterns.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px]">
          {highSeverityCount > 0 && (
            <span className="text-[var(--status-critical)] font-bold">
              {highSeverityCount} High Risk
            </span>
          )}
          {highSeverityCount > 0 && mediumSeverityCount > 0 && (
            <span className="text-[var(--muted-foreground)]">&middot;</span>
          )}
          {mediumSeverityCount > 0 && (
            <span className="text-[var(--status-warning)] font-bold">
              {mediumSeverityCount} Elevated
            </span>
          )}
          {highSeverityCount === 0 && mediumSeverityCount === 0 && (
            <span className="text-[var(--status-success)] font-medium">
              Baseline Signals
            </span>
          )}
        </div>
      </div>

      {/* Category Filter Tabs (Zero-pill discipline: segmented tab bar) */}
      {categories.length > 2 && (
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs border-b border-[var(--border-subtle)]">
          {categories.map((cat) => {
            const isActive = selectedCategory === cat.key;
            return (
              <button
                key={cat.key}
                type="button"
                onClick={() => setSelectedCategory(cat.key)}
                className={`px-3 py-1.5 font-medium rounded-lg text-xs whitespace-nowrap transition-colors cursor-pointer border ${
                  isActive
                    ? 'border-[var(--primary-orange)]/40 bg-[var(--surface-active)] text-[var(--primary-orange)] font-bold'
                    : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]'
                }`}
              >
                {cat.label}{' '}
                <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
                  ({cat.count})
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* Indicators List */}
      {filteredIndicators.length > 0 ? (
        <div className="grid grid-cols-1 gap-3">
          {filteredIndicators.map((item) => {
            const isHigh = item.severity === 'high';
            const isMed = item.severity === 'medium';
            const isLow = item.severity === 'low';

            let accentBorder = 'border-[var(--border-subtle)]';
            let accentBg = 'bg-[var(--surface-interactive)]';
            let badgeBg = 'bg-[var(--border-subtle)] text-[var(--muted-foreground)]';

            if (isHigh) {
              accentBorder = 'border-[var(--status-critical)]/40';
              accentBg = 'bg-[var(--status-critical-bg)]/20';
              badgeBg = 'bg-[var(--status-critical)]/15 text-[var(--status-critical)] border border-[var(--status-critical)]/30';
            } else if (isMed) {
              accentBorder = 'border-[var(--status-warning)]/40';
              accentBg = 'bg-[var(--status-warning-bg)]/20';
              badgeBg = 'bg-[var(--status-warning)]/15 text-[var(--status-warning)] border border-[var(--status-warning)]/30';
            } else if (isLow) {
              accentBorder = 'border-[var(--accent-cyan)]/30';
              accentBg = 'bg-[var(--accent-cyan)]/5';
              badgeBg = 'bg-[var(--accent-cyan)]/15 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30';
            }

            return (
              <div
                key={item.id}
                className={`rounded-xl border p-4 space-y-2 transition-all ${accentBorder} ${accentBg}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {isHigh ? (
                      <AlertOctagon className="h-4 w-4 text-[var(--status-critical)] shrink-0" />
                    ) : isMed ? (
                      <AlertTriangle className="h-4 w-4 text-[var(--status-warning)] shrink-0" />
                    ) : (
                      <Info className="h-4 w-4 text-[var(--accent-cyan)] shrink-0" />
                    )}
                    <h4 className="text-xs sm:text-sm font-bold text-[var(--foreground)]">
                      {item.title}
                    </h4>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-[var(--muted-foreground)]">
                      {item.category.replace('_', ' ')}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${badgeBg}`}>
                      {item.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                  {item.description}
                </p>

                {item.evidence && (
                  <div className="mt-2 rounded-lg bg-[var(--background)] border border-[var(--border)] p-2.5 flex items-center justify-between gap-2 font-mono text-[11px]">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[var(--muted-foreground)] shrink-0 select-none">
                        Evidence:
                      </span>
                      <span
                        className="text-[var(--foreground)] font-semibold truncate max-w-[280px] sm:max-w-[460px]"
                        title={item.evidence}
                      >
                        {item.evidence}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleCopy(item.evidence, item.id)}
                      className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer shrink-0"
                      title="Copy Evidence String"
                    >
                      {copiedId === item.id ? (
                        <Check className="h-3.5 w-3.5 text-[var(--status-success)]" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        /* Clean Baseline State */
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-6 text-center space-y-2">
          <div className="mx-auto w-10 h-10 rounded-full bg-[var(--status-success-bg)] flex items-center justify-center text-[var(--status-success)] border border-[var(--status-success-border)]">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <h4 className="text-xs sm:text-sm font-bold text-[var(--foreground)]">
            No Anomalous Heuristics Detected
          </h4>
          <p className="text-xs text-[var(--foreground-secondary)] max-w-md mx-auto">
            The URL syntax, domain structure, path encoding, and query parameters follow standard web conventions without typical deceptive homoglyphs, IP literal hosts, or credential strings.
          </p>
        </div>
      )}
    </section>
  );
}
