'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import ThreatBadge from '@/components/ui/ThreatBadge';
import {
  Link2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Binary,
  Layers,
  Search,
  ExternalLink,
  Copy,
  Check,
  RotateCcw,
  Server,
  Lock,
  ArrowRight,
  Info,
  ChevronRight,
  AlertCircle,
  FileText,
  UserCheck,
  Terminal,
  Clock,
  Sparkles,
} from 'lucide-react';
import { UrlInvestigationReport } from '@/lib/url-investigation/types';
import { saveSessionUrlInvestigation } from '@/lib/session-store';

interface DemoTarget {
  id: string;
  name: string;
  url: string;
  badge: string;
  description: string;
}

const DEMO_TARGETS: DemoTarget[] = [
  {
    id: 'spoof',
    name: 'Bank Subdomain Spoof',
    url: 'https://secure-login.chase-verification.example.com/auth/verify?session=fake&id=9283',
    badge: 'High Heuristic',
    description: 'Impersonation of corporate financial institution on non-standard subdomain',
  },
  {
    id: 'shortener',
    name: 'Obfuscated Shortener',
    url: 'https://bit.ly/3XampleTestSecure',
    badge: 'Obfuscated',
    description: 'Third-party link redirection masking destination and final payload',
  },
  {
    id: 'freehosting',
    name: 'Free Cloud Hosting Form',
    url: 'https://payroll-update.pages.dev/login.html',
    badge: 'Cloud Abuse',
    description: 'Subdomain hosted on free public cloud hosting platform often abused for phishing',
  },
  {
    id: 'legit',
    name: 'Standard Verified Target',
    url: 'https://www.example.org/about-security',
    badge: 'RFC 2606',
    description: 'Established canonical domain with standard routing and no abuse reports',
  },
];

export default function UrlInvestigationPage() {
  const [inputUrl, setInputUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<UrlInvestigationReport | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const [activePlaybookTab, setActivePlaybookTab] = useState<'individual' | 'secops'>('individual');

  const STAGES = [
    'Syntactic parsing, credential checks & SSRF screening',
    'Querying abuse intelligence (URLhaus) & DNS records',
    'Web context search for brand impersonation & reports',
    'AI threat synthesis & defensive recommendations',
  ];

  const handleSelectDemo = (targetUrl: string) => {
    setInputUrl(targetUrl);
    setError(null);
  };

  const handleClear = () => {
    setInputUrl('');
    setError(null);
    setReport(null);
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const target = inputUrl.trim();
    if (!target) {
      setError('Please provide a URL to investigate.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setActiveStage(0);

    const stageTimer1 = setTimeout(() => setActiveStage(1), 600);
    const stageTimer2 = setTimeout(() => setActiveStage(2), 1400);
    const stageTimer3 = setTimeout(() => setActiveStage(3), 2200);

    try {
      const res = await fetch('/api/url-investigation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });

      clearTimeout(stageTimer1);
      clearTimeout(stageTimer2);
      clearTimeout(stageTimer3);

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to complete URL investigation.');
      }

      setReport(data.report);
      // Save to guest session store if relevant
      if (data.report) {
        saveSessionUrlInvestigation(data.report);
      }
    } catch (err: any) {
      setError(err?.message || 'An unexpected error occurred during investigation.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyJson = () => {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <AppShell>
      <div className="space-y-8 max-w-7xl mx-auto pb-12">
        {/* ========================================================
            1. HEADER & BREADCRUMBS
            ======================================================== */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[var(--border)] pb-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <Link
                href="/"
                className="text-xs text-[var(--muted-foreground)] hover:text-[var(--primary-orange)] transition-colors inline-flex items-center gap-1"
              >
                <span>Dashboard</span>
              </Link>
              <span className="text-xs text-[var(--muted-foreground)]">&middot;</span>
              <span className="text-xs text-[var(--foreground)] font-medium">URL Intelligence</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] flex items-center gap-2.5">
              <div className="h-9 w-9 rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)] flex items-center justify-center">
                <Link2 className="h-5 w-5" />
              </div>
              <span>URL Intelligence</span>
            </h1>
            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-3xl leading-relaxed">
              Investigate suspicious links using available threat intelligence, web evidence, and behavioral indicators.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            <span className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] px-3 py-1.5 text-xs font-mono text-[var(--primary-orange)] font-semibold">
              <span className="h-2 w-2 rounded-full bg-[var(--primary-orange)] animate-pulse" />
              <span>SSRF Protected &middot; URLhaus Grounded</span>
            </span>
          </div>
        </div>

        {/* ========================================================
            2. INPUT & DEMO TARGET SELECTOR
            ======================================================== */}
        <section aria-label="URL Input Area" className="space-y-4">
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <label
                htmlFor="url-input"
                className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2"
              >
                <Search className="h-4 w-4 text-[var(--primary-orange)]" />
                <span>Screen Target Destination</span>
              </label>
              <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                HTTP &amp; HTTPS schemes only
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[var(--muted-foreground)]">
                    <Globe className="h-4 w-4" />
                  </div>
                  <input
                    id="url-input"
                    type="text"
                    value={inputUrl}
                    onChange={(e) => {
                      setInputUrl(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder="https://example.com/login?token=sensitive..."
                    disabled={isLoading}
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--background)] pl-10 pr-10 py-3 text-xs sm:text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:outline-none focus:ring-2 focus:ring-[var(--focus-ring)] focus:border-transparent transition-all font-mono"
                  />
                  {inputUrl && (
                    <button
                      type="button"
                      onClick={handleClear}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer"
                      title="Clear URL"
                    >
                      <RotateCcw className="h-4 w-4" />
                    </button>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={isLoading || !inputUrl.trim()}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-orange-hover)] disabled:opacity-50 disabled:cursor-not-allowed px-6 py-3 text-xs sm:text-sm font-semibold text-white shadow-md shadow-[var(--primary-orange)]/25 transition-all cursor-pointer shrink-0"
                >
                  {isLoading ? (
                    <>
                      <span className="h-4 w-4 rounded-full border-2 border-white border-t-transparent animate-spin" />
                      <span>Screening...</span>
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4" />
                      <span>Investigate URL</span>
                    </>
                  )}
                </button>
              </div>

              {/* Demo Scenarios Quick Pick */}
              <div className="pt-2">
                <div className="text-[11px] font-medium text-[var(--muted-foreground)] mb-2 flex items-center gap-1.5">
                  <Sparkles className="h-3 w-3 text-[var(--primary-orange)]" />
                  <span>Or test with reserved synthetic targets (RFC 2606 / 5737 compliant):</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                  {DEMO_TARGETS.map((demo) => (
                    <button
                      key={demo.id}
                      type="button"
                      onClick={() => handleSelectDemo(demo.url)}
                      disabled={isLoading}
                      className="text-left rounded-xl border border-[var(--border)] bg-[var(--background)]/60 hover:bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40 p-2.5 transition-all cursor-pointer group"
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="text-xs font-semibold text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors truncate">
                          {demo.name}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] border border-[var(--primary-orange)]/20 shrink-0">
                          {demo.badge}
                        </span>
                      </div>
                      <p className="text-[10px] text-[var(--muted-foreground)] line-clamp-1">
                        {demo.description}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            </form>
          </div>

          {/* Validation or Investigation Error */}
          {error && (
            <div
              role="alert"
              className="rounded-2xl border border-[var(--status-critical)]/40 bg-[var(--surface-soft-orange)] p-4 sm:p-5 text-[var(--foreground)] space-y-2 animate-in fade-in duration-200"
            >
              <div className="flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-[var(--status-critical)] shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <h4 className="text-xs sm:text-sm font-bold text-[var(--status-critical)]">
                    URL Screening Interrupted
                  </h4>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    {error}
                  </p>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ========================================================
            3. MULTI-STAGE RADAR TELEMETRY (WHEN SCANNING)
            ======================================================== */}
        {isLoading && (
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 space-y-6 animate-in fade-in duration-300">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/40 text-[var(--primary-orange)] flex items-center justify-center">
                <span className="h-5 w-5 rounded-full border-2 border-[var(--primary-orange)] border-t-transparent animate-spin" />
              </div>
              <div>
                <h3 className="text-sm sm:text-base font-bold text-[var(--foreground)]">
                  Executing URL Telemetry Pipeline
                </h3>
                <p className="text-xs text-[var(--muted-foreground)]">
                  Simultaneous syntactic decomposition, malware database lookup, and DNS trace.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {STAGES.map((label, index) => {
                const isComplete = activeStage > index;
                const isCurrent = activeStage === index;
                return (
                  <div
                    key={index}
                    className={`rounded-xl border p-3 transition-all ${
                      isCurrent
                        ? 'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)]'
                        : isComplete
                        ? 'border-[var(--status-success)]/40 bg-[var(--status-success)]/5'
                        : 'border-[var(--border)] bg-[var(--background)]/40 opacity-50'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      {isComplete ? (
                        <Check className="h-4 w-4 text-[var(--status-success)] shrink-0" />
                      ) : isCurrent ? (
                        <span className="h-3.5 w-3.5 rounded-full border-2 border-[var(--primary-orange)] border-t-transparent animate-spin shrink-0" />
                      ) : (
                        <span className="h-3.5 w-3.5 rounded-full bg-[var(--border)] shrink-0" />
                      )}
                      <span className="text-[11px] font-mono font-bold text-[var(--foreground)]">
                        Phase {index + 1}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--foreground-secondary)] line-clamp-2 leading-tight">
                      {label}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ========================================================
            4. COMPREHENSIVE INVESTIGATION DOSSIER
            ======================================================== */}
        {report && !isLoading && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Dossier Top Banner */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[var(--border-subtle)] pb-5">
                <div className="flex items-start sm:items-center gap-3">
                  <ThreatBadge level={report.overallSeverity} score={report.severityScore} size="md" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold uppercase text-[var(--muted-foreground)]">
                        Threat Score:
                      </span>
                      <span className="font-mono text-sm font-bold text-[var(--foreground)]">
                        {report.severityScore} / 100
                      </span>
                      <span className="text-xs text-[var(--muted-foreground)]">&middot;</span>
                      <span className="text-xs font-mono text-[var(--muted-foreground)]">
                        Confidence: <span className="font-bold text-[var(--foreground)] capitalize">{report.confidenceLevel}</span>
                      </span>
                    </div>
                    <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                      {report.confidenceRationale}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-start sm:self-auto">
                  <button
                    type="button"
                    onClick={handleCopyJson}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--background)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition-colors cursor-pointer"
                  >
                    {copiedJson ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-[var(--status-success)]" />
                        <span>Copied JSON</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5 text-[var(--muted-foreground)]" />
                        <span>Export JSON</span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={handleClear}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--background)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition-colors cursor-pointer"
                  >
                    <RotateCcw className="h-3.5 w-3.5 text-[var(--muted-foreground)]" />
                    <span>New Screening</span>
                  </button>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-1.5">
                <div className="text-xs font-mono font-bold uppercase text-[var(--primary-orange)] flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5" />
                  <span>Executive Assessment</span>
                </div>
                <p className="text-xs sm:text-sm text-[var(--foreground)] leading-relaxed bg-[var(--background)]/60 p-4 rounded-xl border border-[var(--border)] font-sans">
                  {report.executiveSummary}
                </p>
              </div>

              {/* Credentials / Sensitive Parameters Notice if applicable */}
              {report.urlComponents.redactedParamsCount > 0 && (
                <div className="rounded-xl border border-[var(--accent-amber)]/30 bg-[var(--accent-amber)]/5 p-3.5 text-xs flex items-center gap-2.5">
                  <Lock className="h-4 w-4 text-[var(--accent-amber)] shrink-0" />
                  <span className="text-[var(--foreground)]">
                    <strong className="font-semibold text-[var(--accent-amber)]">Sensitive Tokens Redacted:</strong>{' '}
                    {report.urlComponents.redactedParamsCount} potential authentication or session credential(s) in query parameters were masked prior to threat queries to protect user privacy.
                  </span>
                </div>
              )}
            </div>

            {/* Grid 1: URL Decomposition Table & URLhaus Intel */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Card A: Technical Decomposition */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
                  <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                    <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
                    <span>Structural Decomposition</span>
                  </h3>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                    RFC 3986 Standard
                  </span>
                </div>

                <div className="divide-y divide-[var(--border-subtle)] text-xs font-mono">
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Scheme:</span>
                    <span className="text-[var(--foreground)] font-bold">{report.urlComponents.protocol}</span>
                  </div>
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Hostname:</span>
                    <span className="text-[var(--foreground)] font-bold truncate max-w-[280px]" title={report.urlComponents.hostname}>
                      {report.urlComponents.hostname}
                    </span>
                  </div>
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Registerable Domain:</span>
                    <span className="text-[var(--foreground)] font-bold">{report.urlComponents.domain || 'N/A'}</span>
                  </div>
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Port:</span>
                    <span className="text-[var(--foreground)]">{report.urlComponents.port || 'Standard (80/443)'}</span>
                  </div>
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Path:</span>
                    <span className="text-[var(--foreground)] truncate max-w-[280px]" title={report.urlComponents.pathname}>
                      {report.urlComponents.pathname || '/'}
                    </span>
                  </div>
                  <div className="py-2 flex items-center justify-between">
                    <span className="text-[var(--muted-foreground)]">Target Defanged:</span>
                    <span className="text-[var(--foreground)] truncate max-w-[280px]" title={report.urlComponents.displayUrl}>
                      {report.urlComponents.displayUrl}
                    </span>
                  </div>
                </div>
              </div>

              {/* Card B: Abuse Database & Malware Intelligence (URLhaus) */}
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
                  <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                    <Binary className="h-4 w-4 text-[var(--primary-orange)]" />
                    <span>Malware Threat Intelligence</span>
                  </h3>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                    URLhaus Registry
                  </span>
                </div>

                {report.threatIntel && report.threatIntel.length > 0 ? (
                  <div className="space-y-3">
                    {report.threatIntel.map((intel, idx) => (
                      <div
                        key={idx}
                        className={`rounded-xl border p-3.5 space-y-2 text-xs font-mono ${
                          intel.status === 'malicious'
                            ? 'border-[var(--status-critical)]/40 bg-[var(--status-critical)]/5'
                            : 'border-[var(--border)] bg-[var(--background)]/60'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-bold text-[var(--foreground)] truncate max-w-[280px]">
                            Indicator: {intel.indicator}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                              intel.status === 'malicious'
                                ? 'bg-[var(--status-critical)]/20 text-[var(--status-critical)]'
                                : 'bg-[var(--muted)] text-[var(--muted-foreground)]'
                            }`}
                          >
                            {intel.provider} &middot; {intel.status.toUpperCase()}
                          </span>
                        </div>
                        {intel.threatType && (
                          <div className="text-[var(--foreground-secondary)]">
                            <span className="text-[var(--muted-foreground)]">Threat Classification:</span> {intel.threatType}
                          </div>
                        )}
                        {intel.tags && intel.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {intel.tags.map((t, tid) => (
                              <span
                                key={tid}
                                className="rounded bg-[var(--background)] px-1.5 py-0.5 text-[9px] border border-[var(--border)] text-[var(--foreground-secondary)]"
                              >
                                #{t}
                              </span>
                            ))}
                          </div>
                        )}
                        {intel.details && (
                          <p className="text-[11px] font-sans text-[var(--foreground-secondary)]">
                            {intel.details}
                          </p>
                        )}
                        {intel.importantNotice && (
                          <p className="text-[10px] font-mono text-[var(--accent-amber)]">
                            {intel.importantNotice}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/40 p-4 text-center space-y-1">
                    <p className="text-xs text-[var(--foreground-secondary)]">
                      No matching records identified in active URLhaus malware databases.
                    </p>
                  </div>
                )}

                {/* Explicit Disclaimer */}
                <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/40 p-3 text-[11px] text-[var(--muted-foreground)] flex items-start gap-2">
                  <Info className="h-4 w-4 shrink-0 text-[var(--primary-orange)] mt-0.5" />
                  <span>
                    <strong>Telemetry Disclaimer:</strong> An unlisted result in URLhaus confirms the link has not been reported as a known malware distribution endpoint; it does <em>not</em> guarantee that newly registered or targeted phishing sites are safe.
                  </span>
                </div>
              </div>
            </div>

            {/* Grid 2: DNS & Network Routing Telemetry */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
                <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                  <Server className="h-4 w-4 text-[var(--accent-cyan)]" />
                  <span>DNS &amp; Routing Telemetry</span>
                </h3>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                  Live Authoritative Resolvers
                </span>
              </div>

              {report.domainIntelligence ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3 space-y-1">
                      <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Resolved IP Addresses</span>
                      <div className="text-[var(--foreground)] font-bold truncate">
                        {report.domainIntelligence.ipAddresses && report.domainIntelligence.ipAddresses.length > 0
                          ? report.domainIntelligence.ipAddresses.join(', ')
                          : 'None resolved'}
                      </div>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3 space-y-1">
                      <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Mail Routing (MX)</span>
                      <div className="text-[var(--foreground)] font-bold truncate">
                        {report.domainIntelligence.hasMailServers
                          ? `${report.domainIntelligence.mxRecordsCount} MX host(s) configured`
                          : 'No MX records declared'}
                      </div>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3 space-y-1">
                      <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Infrastructure Status</span>
                      <div className={`font-bold truncate ${report.domainIntelligence.isSuspiciousOrParked ? 'text-[var(--status-critical)]' : 'text-[var(--status-success)]'}`}>
                        {report.domainIntelligence.isSuspiciousOrParked ? 'Anomalous / Parked Domain' : 'Active Zone Routing'}
                      </div>
                    </div>
                  </div>
                  {report.domainIntelligence.notes && (
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/40 p-3 text-xs text-[var(--foreground-secondary)] font-mono">
                      {report.domainIntelligence.notes}
                    </div>
                  )}
                  {report.domainIntelligence.caveat && (
                    <div className="text-[10px] font-mono text-[var(--muted-foreground)] italic px-1">
                      Caveat: {report.domainIntelligence.caveat}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-[var(--muted-foreground)]">
                  DNS resolution deferred or unavailable for this hostname.
                </p>
              )}
            </div>

            {/* Grid 3: Behavioral Indicators & Heuristics */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
                <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-[var(--primary-orange)]" />
                  <span>Behavioral &amp; Structural Indicators</span>
                </h3>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                  {report.indicators.length} Indicator(s) Flagged
                </span>
              </div>

              {report.indicators.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {report.indicators.map((ind) => (
                    <div
                      key={ind.id}
                      className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3.5 space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-[var(--foreground)] truncate">
                          {ind.title}
                        </span>
                        <span
                          className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded font-bold ${
                            ind.severity === 'high'
                              ? 'bg-[var(--status-critical)]/20 text-[var(--status-critical)] border border-[var(--status-critical)]/30'
                              : ind.severity === 'medium'
                              ? 'bg-[var(--accent-amber)]/20 text-[var(--accent-amber)] border border-[var(--accent-amber)]/30'
                              : 'bg-[var(--muted)] text-[var(--muted-foreground)] border border-[var(--border)]'
                          }`}
                        >
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                        {ind.description}
                      </p>
                      {ind.evidence && (
                        <div className="text-[10px] font-mono text-[var(--muted-foreground)] bg-[var(--background)] p-1.5 rounded border border-[var(--border-subtle)] truncate">
                          Evidence: {ind.evidence}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-xl border border-[var(--status-success)]/30 bg-[var(--status-success)]/5 p-4 text-center">
                  <p className="text-xs text-[var(--foreground)]">
                    No deceptive behavioral patterns or high-risk syntactic anomalies detected.
                  </p>
                </div>
              )}
            </div>

            {/* Grid 4: Web Research Sources (if any) */}
            {report.webEvidence && report.webEvidence.length > 0 && (
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
                  <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                    <Globe className="h-4 w-4 text-[var(--accent-violet)]" />
                    <span>Corroborating Web Evidence</span>
                  </h3>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                    Live Web Discovery
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {report.webEvidence.map((src, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3.5 space-y-1.5 flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className="text-xs font-bold text-[var(--foreground)] truncate" title={src.title}>
                            {src.title}
                          </span>
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--accent-violet)]/10 text-[var(--accent-violet)] border border-[var(--accent-violet)]/20 shrink-0">
                            {src.domain}
                          </span>
                        </div>
                        <p className="text-xs text-[var(--foreground-secondary)] line-clamp-3 leading-relaxed">
                          {src.snippet}
                        </p>
                      </div>
                      <div className="pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)] truncate">
                        Source: {src.url}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Grid 5: Actionable Defensive Playbooks (Dual Tab Audience) */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
                <div>
                  <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-[var(--primary-orange)]" />
                    <span>Defensive Response Playbook</span>
                  </h3>
                  <p className="text-xs text-[var(--muted-foreground)] mt-0.5">
                    Recommended containment and defensive measures tailored by operational role.
                  </p>
                </div>

                {/* Tabs: Individual vs SecOps */}
                <div className="flex items-center gap-1 rounded-xl bg-[var(--background)] p-1 border border-[var(--border)]">
                  <button
                    type="button"
                    onClick={() => setActivePlaybookTab('individual')}
                    className={`rounded-lg px-3 py-1 text-xs font-semibold transition-all cursor-pointer ${
                      activePlaybookTab === 'individual'
                        ? 'bg-[var(--primary-orange)] text-white shadow-sm'
                        : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)]'
                    }`}
                  >
                    For Individuals
                  </button>
                  <button
                    type="button"
                    onClick={() => setActivePlaybookTab('secops')}
                    className={`rounded-lg px-3 py-1 text-xs font-semibold transition-all cursor-pointer ${
                      activePlaybookTab === 'secops'
                        ? 'bg-[var(--primary-orange)] text-white shadow-sm'
                        : 'text-[var(--muted-foreground)] hover:text-[var(--foreground)]'
                    }`}
                  >
                    For SecOps / IR
                  </button>
                </div>
              </div>

              {activePlaybookTab === 'individual' ? (
                <ul className="space-y-2 text-xs text-[var(--foreground)]">
                  {report.recommendedActions.forIndividuals.map((action, idx) => (
                    <li
                      key={idx}
                      className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3 flex items-start gap-2.5"
                    >
                      <UserCheck className="h-4 w-4 text-[var(--primary-orange)] shrink-0 mt-0.5" />
                      <span className="leading-relaxed">{action}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <ul className="space-y-2 text-xs text-[var(--foreground)]">
                  {(report.recommendedActions?.forSecurityTeams || []).map((action, idx) => (
                    <li
                      key={idx}
                      className="rounded-xl border border-[var(--border)] bg-[var(--background)]/60 p-3 flex items-start gap-2.5 font-mono text-[11px]"
                    >
                      <Terminal className="h-4 w-4 text-[var(--accent-cyan)] shrink-0 mt-0.5" />
                      <span className="leading-relaxed">{action}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Grid 6: Limitations & Forensic Verification Boundary */}
            {report.evidenceLimitations && report.evidenceLimitations.length > 0 && (
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 text-xs text-[var(--muted-foreground)] space-y-2">
                <span className="font-bold text-[var(--foreground)] uppercase text-[10px] tracking-wider block">
                  Investigation Limitations &amp; Boundaries
                </span>
                <ul className="list-disc list-inside space-y-1 text-[11px] leading-relaxed">
                  {report.evidenceLimitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}
