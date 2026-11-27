'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import {
  Link2,
  ShieldAlert,
  Copy,
  Check,
  RotateCcw,
  FileCode,
  Sparkles,
  Search,
  CheckCircle2,
} from 'lucide-react';
import { UrlInvestigationReport } from '@/lib/url-investigation/types';
import { saveSessionUrlInvestigation } from '@/lib/session-store';
import { useQuota } from '@/hooks/use-quota';
import { isCapabilityExhausted } from '@/lib/quota-types';
import QuotaStatusBanner from '@/components/QuotaStatusBanner';

// Modular URL Intelligence Components
import IntelligenceRadar from '@/components/url-intelligence/IntelligenceRadar';
import RiskGauge from '@/components/url-intelligence/RiskGauge';
import TargetDecomposition from '@/components/url-intelligence/TargetDecomposition';
import DnsTelemetryCard from '@/components/url-intelligence/DnsTelemetryCard';
import UrlhausCard from '@/components/url-intelligence/UrlhausCard';
import BehavioralIndicatorsCard from '@/components/url-intelligence/BehavioralIndicatorsCard';
import ResponsePlaybook from '@/components/url-intelligence/ResponsePlaybook';
import InvestigationConsole from '@/components/url-intelligence/InvestigationConsole';

const PIPELINE_STAGES = [
  'Syntactic parsing, credential checks & SSRF screening',
  'Querying abuse intelligence (URLhaus) & DNS records',
  'Web context search for brand impersonation & reports',
  'AI threat synthesis & defensive recommendations',
];

export default function UrlInvestigationPage() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<UrlInvestigationReport | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);

  const {
    quota,
    loading: quotaLoading,
    error: quotaError,
    errorCode: quotaErrorCode,
    requiresVerification,
    refreshQuota,
    updateQuotaSnapshot,
  } = useQuota();

  const isQuotaBlocked = requiresVerification || isCapabilityExhausted(quota, 'url_investigation');

  const handleClear = () => {
    setUrl('');
    setError(null);
    setReport(null);
  };

  const handleInvestigate = async (overrideUrl?: string) => {
    const target = (overrideUrl || url).trim();
    if (!target) {
      setError('Please provide a URL or hostname to investigate.');
      return;
    }

    if (isQuotaBlocked) {
      setError(
        requiresVerification
          ? 'Please verify your email address to unlock registered URL Intelligence credits.'
          : 'URL Intelligence credits are exhausted for this account.'
      );
      return;
    }

    setIsLoading(true);
    setError(null);
    setActiveStage(0);

    const timer1 = setTimeout(() => setActiveStage(1), 600);
    const timer2 = setTimeout(() => setActiveStage(2), 1400);
    const timer3 = setTimeout(() => setActiveStage(3), 2200);

    try {
      const res = await fetch('/api/url-investigation', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });

      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);

      const data = await res.json().catch(() => null);
      if (data?.quota) {
        updateQuotaSnapshot(data.quota);
      }

      if (!res.ok) {
        if (
          data?.errorCode === 'quota_exhausted' ||
          data?.errorCode === 'invalid_guest_token' ||
          data?.errorCode === 'email_verification_required' ||
          data?.errorCode === 'quota_service_unavailable'
        ) {
          refreshQuota();
          throw new Error(data?.error || 'Investigation credit check prevented execution.');
        }

        const baseError = data?.error || 'Investigation could not be completed.';
        if (data?.errorCode === 'rate_limiter_unavailable') {
          throw new Error(`Rate-Limit Protection Unavailable: ${baseError}`);
        }
        if (data?.errorCode === 'rate_limit_exceeded' || res.status === 429) {
          throw new Error(`Request Rate Limit Reached: ${baseError}`);
        }
        throw new Error(baseError);
      }

      setReport(data.report);
      if (!data?.quota) {
        refreshQuota();
      }

      // Persist in guest/local session store
      if (data.report) {
        saveSessionUrlInvestigation(data.report);
      }
    } catch (err: any) {
      setError(err?.message || 'An unexpected error occurred during URL investigation.');
      refreshQuota();
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
      <div className="space-y-8 max-w-7xl mx-auto pb-16">
        {/* ========================================================
            1. HEADER & SYSTEM STATUS BADGES
            ======================================================== */}
        <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[var(--border)] pb-6">
          <div className="space-y-1.5">
            <nav className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
              <Link
                href="/"
                className="hover:text-[var(--primary-orange)] transition-colors inline-flex items-center gap-1"
              >
                <span>Dashboard</span>
              </Link>
              <span aria-hidden="true">&middot;</span>
              <span className="text-[var(--foreground)] font-medium">URL Intelligence</span>
            </nav>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] flex items-center gap-2.5">
              <div className="h-9 w-9 rounded-xl bg-[var(--surface-active)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)] flex items-center justify-center">
                <Link2 className="h-5 w-5" />
              </div>
              <span>URL Intelligence &amp; Digital Forensics</span>
            </h1>

            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-3xl leading-relaxed">
              Deep-screen suspicious destinations using authoritative malware feeds, real-time DNS telemetry, RFC 3986 structural decomposition, and behavioral heuristics.
            </p>
          </div>

          {/* Telemetry Status & Actions */}
          <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
            <span className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--primary-orange)]/30 bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-mono text-[var(--primary-orange)] font-semibold">
              <span className="h-2 w-2 rounded-full bg-[var(--primary-orange)] animate-pulse" />
              <span>SSRF Protected &middot; URLhaus Grounded</span>
            </span>

            {report && (
              <>
                <button
                  type="button"
                  onClick={handleCopyJson}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--card-bg)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-mono text-[var(--foreground)] transition-colors cursor-pointer"
                  title="Export Report Telemetry as JSON"
                >
                  {copiedJson ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-[var(--status-success)]" />
                      <span>Copied JSON</span>
                    </>
                  ) : (
                    <>
                      <FileCode className="h-3.5 w-3.5 text-[var(--muted-foreground)]" />
                      <span>Export JSON</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleClear}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--card-bg)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-mono text-[var(--foreground)] transition-colors cursor-pointer"
                  title="Clear Investigation and Screen New Target"
                >
                  <RotateCcw className="h-3.5 w-3.5 text-[var(--muted-foreground)]" />
                  <span>Reset</span>
                </button>
              </>
            )}
          </div>
        </header>

        {/* Quota Allowance Banner */}
        <QuotaStatusBanner
          quota={quota}
          loading={quotaLoading}
          error={quotaError}
          errorCode={quotaErrorCode}
          requiresVerification={requiresVerification}
          activeCapability="url_investigation"
        />

        {/* ========================================================
            2. PRIMARY INVESTIGATION CONSOLE
            ======================================================== */}
        <section aria-label="Investigation Console">
          <InvestigationConsole
            url={url}
            setUrl={setUrl}
            isLoading={isLoading}
            onInvestigate={handleInvestigate}
            onClear={handleClear}
            error={error}
            quotaExhausted={isQuotaBlocked}
          />
        </section>

        {/* ========================================================
            3. MULTI-STAGE PIPELINE PROGRESS (DURING INVESTIGATION)
            ======================================================== */}
        {isLoading && (
          <section
            aria-label="Multi-stage Telemetry Progress"
            className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 space-y-6 shadow-sm animate-in fade-in duration-300"
          >
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-[var(--surface-active)] border border-[var(--primary-orange)]/40 text-[var(--primary-orange)] flex items-center justify-center">
                <span className="h-5 w-5 rounded-full border-2 border-[var(--primary-orange)] border-t-transparent animate-spin" />
              </div>
              <div>
                <h3 className="text-sm sm:text-base font-bold text-[var(--foreground)]">
                  Executing Intelligence Pipeline
                </h3>
                <p className="text-xs text-[var(--muted-foreground)]">
                  Syntactic decomposition, malware feed cross-reference, and DNS routing trace.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {PIPELINE_STAGES.map((label, index) => {
                const isComplete = activeStage > index;
                const isCurrent = activeStage === index;
                return (
                  <div
                    key={index}
                    className={`rounded-xl border p-3.5 transition-all ${
                      isCurrent
                        ? 'border-[var(--primary-orange)] bg-[var(--surface-active)] shadow-xs'
                        : isComplete
                        ? 'border-[var(--status-success)]/40 bg-[var(--status-success)]/5'
                        : 'border-[var(--border-subtle)] bg-[var(--surface-interactive)]/40 opacity-60'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      {isComplete ? (
                        <Check className="h-4 w-4 text-[var(--status-success)] shrink-0" />
                      ) : isCurrent ? (
                        <span className="h-3.5 w-3.5 rounded-full border-2 border-[var(--primary-orange)] border-t-transparent animate-spin shrink-0" />
                      ) : (
                        <span className="h-2 w-2 rounded-full bg-[var(--muted-foreground)]/50 shrink-0" />
                      )}
                      <span className="text-[10px] font-mono uppercase font-bold text-[var(--muted-foreground)]">
                        Phase {index + 1}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--foreground)] font-medium leading-snug">
                      {label}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* ========================================================
            4. RADAR & RISK GAUGE OVERVIEW
            ======================================================== */}
        <section aria-label="Intelligence Radar and Risk Overview">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            {/* Circular Radar Instrument (5 cols on lg) */}
            <div className="lg:col-span-5 flex flex-col">
              <IntelligenceRadar
                isLoading={isLoading}
                activeStage={activeStage}
                report={report}
                className="h-full min-h-[320px]"
              />
            </div>

            {/* Risk Assessment Instrument or Standby Guidance (7 cols on lg) */}
            <div className="lg:col-span-7 flex flex-col justify-between">
              {report ? (
                <RiskGauge
                  score={report.severityScore}
                  severity={report.overallSeverity}
                  confidenceLevel={report.confidenceLevel}
                  confidenceRationale={report.confidenceRationale}
                  isUnlisted={report.threatIntel.some((i) => i.status === 'clean_or_unlisted')}
                />
              ) : (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 flex flex-col justify-center space-y-4 h-full shadow-sm">
                  <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-[var(--primary-orange)] font-bold">
                    <Sparkles className="h-4 w-4" />
                    <span>Telemetry Command Standby</span>
                  </div>
                  <h3 className="text-lg sm:text-xl font-bold text-[var(--foreground)]">
                    Forensic Destination Screening Ready
                  </h3>
                  <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
                    Input any target link or select a synthetic test case above to trigger synchronous forensic parsing. The multi-tiered analysis validates IP literal targets, extracts RFC 3986 tokens, queries the abuse.ch URLhaus malware registry, and surfaces actionable containment playbooks.
                  </p>
                  <div className="pt-3 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-4 text-xs font-mono text-[var(--muted-foreground)]">
                    <span>Protocol: RFC 3986</span>
                    <span>&middot;</span>
                    <span>Feed: abuse.ch URLhaus</span>
                    <span>&middot;</span>
                    <span>Protection: SSRF Filtered</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ========================================================
            5. EXECUTIVE SUMMARY & FORENSIC DOSSIER (WHEN RESOLVED)
            ======================================================== */}
        {report && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Executive Summary Card */}
            {report.executiveSummary && (
              <section
                aria-label="Executive Intelligence Summary"
                className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-2.5 border-l-4 border-l-[var(--primary-orange)]"
              >
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] font-mono">
                    Executive Intelligence Summary
                  </h3>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                    {new Date(report.investigatedAt).toLocaleString()}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-[var(--foreground)] leading-relaxed">
                  {report.executiveSummary}
                </p>
              </section>
            )}

            {/* Target Decomposition */}
            <TargetDecomposition urlComponents={report.urlComponents} />

            {/* Twin Telemetry Grid: URLhaus Feed & DNS Telemetry */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
              <UrlhausCard threatIntel={report.threatIntel} />
              <DnsTelemetryCard dns={report.domainIntelligence} />
            </div>

            {/* Behavioral Indicators Card */}
            <BehavioralIndicatorsCard indicators={report.indicators} />

            {/* Mitigation Playbook, OSINT Evidence & Forensic Scope */}
            <ResponsePlaybook
              recommendations={report.recommendedActions}
              webEvidence={report.webEvidence}
              limitations={report.evidenceLimitations}
              modelUsed={report.modelUsed}
            />
          </div>
        )}
      </div>
    </AppShell>
  );
}
