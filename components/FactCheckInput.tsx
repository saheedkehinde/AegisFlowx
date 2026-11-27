'use client';

import React, { useState, useRef } from 'react';
import {
  Globe,
  Search,
  Loader2,
  AlertCircle,
  ShieldCheck,
  Info,
  ChevronDown,
  ChevronUp,
  Landmark,
  FileText,
  ShieldAlert,
  MessageSquare,
} from 'lucide-react';
import { FactCheckReport } from '@/lib/fact-checker/types';
import Link from 'next/link';
import { useQuota } from '@/hooks/use-quota';
import { isCapabilityExhausted, createAttemptIdempotencyKey } from '@/lib/quota-types';

interface FactCheckInputProps {
  onReportComplete: (report: FactCheckReport) => void;
  onCheckStart?: () => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  initialText?: string;
}

export default function FactCheckInput({
  onReportComplete,
  onCheckStart,
  isLoading,
  setIsLoading,
  initialText = '',
}: FactCheckInputProps) {
  const { quota, updateQuotaSnapshot, refreshQuota } = useQuota();
  const isQuotaBlocked = isCapabilityExhausted(quota, 'fact_check');
  const [text, setText] = useState<string>(() => {
    if (initialText) return initialText;
    if (typeof window !== 'undefined') {
      const preloaded = sessionStorage.getItem('aegisflow_factcheck_preload');
      if (preloaded) {
        sessionStorage.removeItem('aegisflow_factcheck_preload');
        return preloaded;
      }
    }
    return '';
  });
  const [error, setError] = useState<string | null>(null);
  const [requiresRegistration, setRequiresRegistration] = useState(false);
  const [showConfigGuide, setShowConfigGuide] = useState(false);
  const inFlightRef = useRef(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim() || isLoading || inFlightRef.current || isQuotaBlocked) return;

    inFlightRef.current = true;
    onCheckStart?.();
    setIsLoading(true);
    setError(null);
    setRequiresRegistration(false);

    try {
      const res = await fetch('/api/fact-check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-aegis-idempotency-key': createAttemptIdempotencyKey(),
        },
        credentials: 'same-origin',
        body: JSON.stringify({ text: text.trim() }),
      });

      const data = await res.json().catch(() => null);
      if (data?.quota) {
        updateQuotaSnapshot(data.quota);
      } else if (res.status !== 400) {
        refreshQuota();
      }

      if (!res.ok) {
        const baseError = data?.error || `Fact-check request failed with status ${res.status}`;
        if (data?.errorCode === 'quota_exhausted' || data?.errorCode === 'invalid_guest_token') {
          setRequiresRegistration(Boolean(data?.requiresRegistration));
          throw new Error(baseError);
        }
        if (data?.errorCode === 'email_verification_required') {
          throw new Error(baseError);
        }
        if (data?.errorCode === 'rate_limiter_unavailable') {
          throw new Error(`Rate-Limit Protection Unavailable: ${baseError}`);
        }
        if (data?.errorCode === 'rate_limit_exceeded' || res.status === 429) {
          throw new Error(`Request Quota Reached: ${baseError}`);
        }
        throw new Error(baseError);
      }

      if (!data?.report) {
        throw new Error('Server returned an empty fact-check report.');
      }

      onReportComplete(data.report);
    } catch (err: any) {
      setError(err?.message || 'Failed to complete web research fact check.');
    } finally {
      inFlightRef.current = false;
      setIsLoading(false);
    }
  };

  const loadSample = (type: 'bank' | 'invoice' | 'crypto' | 'conversational') => {
    if (type === 'bank') {
      setText(
        'WELLS FARGO ALERT: An unauthorized debit of $1,429.99 was flagged on your account. To dispute this charge and avoid an account freeze, verify identity within 15 minutes at https://wf-secure-verify.com or call our fraud department.'
      );
    } else if (type === 'invoice') {
      setText(
        'INVOICE #9410 from Geek Squad Best Buy: Your annual auto-renewal subscription of $499.99 will be charged to your checking account today. To cancel or request a full refund, contact customer support immediately at +1-800-555-0199.'
      );
    } else if (type === 'crypto') {
      setText(
        'IRS Tax Refund Notice: You have an unclaimed federal tax refund of $820.00 from 2025. Submit your direct deposit routing number and SSN at https://irs-tax-refund-portal.gov.us.org within 24 hours to claim.'
      );
    } else {
      setText('Hello, can you attend to me? I wanted to ask how you are doing today.');
    }
    setError(null);
  };

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-7 shadow-[var(--shadow-sm)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-4">
          <div>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] px-2.5 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] font-semibold mb-1.5">
              <Globe className="h-3 w-3" aria-hidden="true" />
              <span>Evidence-Based Web Research &amp; Fact-Checking</span>
            </span>
            <h3 className="text-lg font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Investigate Claims, Communications, Invoices &amp; URLs
            </h3>
            <p className="mt-1 text-xs text-[var(--foreground-secondary)] max-w-2xl leading-relaxed">
              Dissects factual claims from opinions, retrieves public web evidence, interrogates authoritative DNS records, and provides verifiable source citations.
            </p>
          </div>

          <button
            type="button"
            aria-expanded={showConfigGuide}
            onClick={() => setShowConfigGuide(!showConfigGuide)}
            className="self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-mono text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] px-2.5 py-1.5 rounded-lg border border-[var(--accent-cyan)]/30 hover:opacity-90 transition-opacity cursor-pointer shrink-0"
          >
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Evidence Methodology</span>
            {showConfigGuide ? <ChevronUp className="h-3 w-3" aria-hidden="true" /> : <ChevronDown className="h-3 w-3" aria-hidden="true" />}
          </button>
        </div>

        {/* Collapsible Evidence Methodology Guide */}
        {showConfigGuide && (
          <div className="rounded-xl border border-[var(--accent-cyan)]/30 bg-[var(--surface-interactive)] p-4 text-xs space-y-3">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-[var(--accent-cyan)] shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <h5 className="font-semibold text-[var(--foreground)]">Aegis AI Research &amp; Evidence Verification Standards</h5>
                <p className="text-[var(--foreground-secondary)] text-[11px] mt-1 leading-relaxed">
                  AegisFlow evaluates statements using multi-source evidence grounding. Claims are decomposed into verifiable propositions, checked against official regulatory notices, and cross-referenced with global threat intelligence networks.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              <div className="rounded-lg bg-[var(--background-secondary)] border border-[var(--accent-cyan)]/25 p-3 space-y-1">
                <span className="text-[10px] font-mono text-[var(--accent-cyan)] block font-semibold">Authoritative Source Grounding</span>
                <p className="text-[11px] text-[var(--foreground-secondary)]">
                  Prioritizes primary institutional announcements, regulatory circulars, and verified reporting over unverified commentary.
                </p>
              </div>

              <div className="rounded-lg bg-[var(--background-secondary)] border border-[var(--accent-violet)]/25 p-3 space-y-1">
                <span className="text-[10px] font-mono text-[var(--accent-violet)] block font-semibold">Threat Infrastructure Screening</span>
                <p className="text-[11px] text-[var(--foreground-secondary)]">
                  Interrogates DNS zones and malicious infrastructure indicators in real-time with strict SSRF defense.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Quick Sample Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Preset Scenarios:</span>
          <button
            type="button"
            onClick={() => loadSample('bank')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors cursor-pointer"
          >
            <Landmark className="h-3 w-3 text-[var(--primary-orange)]" aria-hidden="true" />
            <span>Wells Fargo Wire Alert</span>
          </button>
          <button
            type="button"
            onClick={() => loadSample('invoice')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors cursor-pointer"
          >
            <FileText className="h-3 w-3 text-[var(--accent-amber)]" aria-hidden="true" />
            <span>Geek Squad Renewal Invoice</span>
          </button>
          <button
            type="button"
            onClick={() => loadSample('crypto')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors cursor-pointer"
          >
            <ShieldAlert className="h-3 w-3 text-[var(--status-critical)]" aria-hidden="true" />
            <span>IRS Refund Phishing Notice</span>
          </button>
          <button
            type="button"
            onClick={() => loadSample('conversational')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] px-2.5 py-1 text-[11px] text-[var(--accent-violet)] hover:opacity-90 transition-opacity cursor-pointer"
          >
            <MessageSquare className="h-3 w-3" aria-hidden="true" />
            <span>Conversational Greeting (Non-Factual)</span>
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="factcheck-claim-input" className="sr-only">
              Claim, message, invoice, or URL to fact-check
            </label>
            <textarea
              id="factcheck-claim-input"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste suspicious message, invoice claim, email body, URL, or public assertion to cross-examine against public evidence..."
              rows={5}
              disabled={isLoading}
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-4 text-xs sm:text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)] font-mono transition-colors resize-y"
            />
            <div className="flex flex-wrap items-center justify-between gap-2 mt-1.5 text-[11px] text-[var(--muted-foreground)] font-mono">
              <span className="tabular-nums">{text.length} / 6,000 characters</span>
              <span>Primary evidence prioritizes official advisories &amp; DNS telemetry</span>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3 text-xs text-[var(--status-critical)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"
            >
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
              {requiresRegistration && (
                <Link
                  href="/auth/register"
                  className="self-start sm:self-auto inline-flex items-center rounded-lg bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] transition-colors shrink-0"
                >
                  Create Free Account
                </Link>
              )}
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
            <span className="text-[11px] text-[var(--foreground-secondary)]">
              Untrusted URLs are never visited automatically. SSRF defenses strictly enforced.
            </span>

            <button
              type="submit"
              disabled={isLoading || !text.trim() || isQuotaBlocked}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-6 py-2.5 text-xs sm:text-sm font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  <span>Researching Evidence Across Web...</span>
                </>
              ) : isQuotaBlocked ? (
                <>
                  <AlertCircle className="h-4 w-4" aria-hidden="true" />
                  <span>Credits Exhausted</span>
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" aria-hidden="true" />
                  <span>Execute Evidence-Based Fact-Check</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
