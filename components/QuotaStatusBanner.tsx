'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  AlertTriangle,
  UserPlus,
  LogIn,
  MessageSquare,
  FileSearch,
  Globe,
  Link2,
  Loader2,
  Lock,
} from 'lucide-react';
import {
  CAPABILITY_LABELS,
  type QuotaCapability,
  type QuotaSnapshot,
  type QuotaErrorCode,
} from '@/lib/quota-types';

interface QuotaStatusBannerProps {
  quota: QuotaSnapshot | null;
  loading: boolean;
  error?: string | null;
  errorCode?: QuotaErrorCode | null;
  requiresVerification?: boolean;
  activeCapability?: QuotaCapability;
  compact?: boolean;
}

const CAPABILITY_ITEMS: {
  key: QuotaCapability;
  label: string;
  shortLabel: string;
  icon: typeof MessageSquare;
  href: string;
}[] = [
  {
    key: 'message_analysis',
    label: CAPABILITY_LABELS.message_analysis,
    shortLabel: 'Messages',
    icon: MessageSquare,
    href: '/analyze?tab=message',
  },
  {
    key: 'document_scan',
    label: CAPABILITY_LABELS.document_scan,
    shortLabel: 'Documents',
    icon: FileSearch,
    href: '/analyze?tab=document',
  },
  {
    key: 'fact_check',
    label: CAPABILITY_LABELS.fact_check,
    shortLabel: 'Fact-Check',
    icon: Globe,
    href: '/analyze?tab=factcheck',
  },
  {
    key: 'url_investigation',
    label: CAPABILITY_LABELS.url_investigation,
    shortLabel: 'URL Intel',
    icon: Link2,
    href: '/url-investigation',
  },
];

export default function QuotaStatusBanner({
  quota,
  loading,
  error,
  errorCode,
  requiresVerification,
  activeCapability,
  compact = false,
}: QuotaStatusBannerProps) {
  if (loading && !quota) {
    return (
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] px-4 py-3 flex items-center gap-2.5 text-xs text-[var(--foreground-secondary)]">
        <Loader2 className="h-4 w-4 animate-spin text-[var(--primary-orange)]" />
        <span>Verifying investigation credit allowance...</span>
      </div>
    );
  }

  if (requiresVerification || errorCode === 'email_verification_required') {
    return (
      <div
        role="alert"
        className="rounded-2xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-4 text-xs text-[var(--foreground)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3"
      >
        <div className="flex items-start gap-2.5">
          <Lock className="h-4 w-4 text-[var(--status-warning)] shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-[var(--status-warning)]">
              Email Confirmation Required
            </p>
            <p className="text-[var(--foreground-secondary)] mt-0.5">
              Verify your email address to activate your 20 registered investigation credits (5 per capability).
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!quota) {
    if (!error) return null;
    return (
      <div
        role="alert"
        className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] px-4 py-3 text-xs text-[var(--status-critical)] flex items-center gap-2"
      >
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>{error}</span>
      </div>
    );
  }

  if (quota.ownerType === 'guest') {
    const remaining = quota.sharedRemaining ?? quota.totalRemaining;
    const limit = quota.sharedLimit ?? 12;
    const exhausted = remaining <= 0;
    const pct = Math.max(0, Math.min(100, Math.round((remaining / limit) * 100)));

    return (
      <section
        aria-label="Guest Investigation Quota"
        className={`rounded-2xl border p-4 sm:p-5 transition-colors shadow-sm ${
          exhausted
            ? 'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)]'
            : 'border-[var(--border)] bg-[var(--card-bg)]'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
              {exhausted ? (
                <AlertTriangle className="h-4 w-4 text-[var(--status-critical)] shrink-0" />
              ) : (
                <ShieldCheck className="h-4 w-4 text-[var(--primary-orange)] shrink-0" />
              )}
              <span>
                {exhausted
                  ? 'Guest Investigation Credits Exhausted (0 / 12 Remaining)'
                  : `${remaining} of ${limit} Guest Investigations Remaining`}
              </span>
            </div>
            <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
              {exhausted
                ? 'Your non-renewing 12-credit guest allowance has been used across AegisFlow tools. Create a free account and verify your email to unlock 20 registered credits (5 per tool).'
                : 'Shared allowance across Message Analysis, Document Scan, Web Fact-Checking, and URL Intelligence. Non-renewing; create an account anytime for 5 credits per capability.'}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Link
              href="/auth/register"
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3.5 py-2 text-xs font-semibold text-[var(--primary-foreground)] shadow-sm transition-colors"
            >
              <UserPlus className="h-3.5 w-3.5" />
              <span>{exhausted ? 'Create Free Account' : 'Unlock 20 Credits'}</span>
            </Link>
            {exhausted && (
              <Link
                href="/auth/login"
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3 py-2 text-xs font-medium text-[var(--foreground)] transition-colors"
              >
                <LogIn className="h-3.5 w-3.5" />
                <span>Sign In</span>
              </Link>
            )}
          </div>
        </div>

        {!compact && (
          <div className="mt-3">
            <div className="h-1.5 w-full rounded-full bg-[var(--surface-interactive)] overflow-hidden border border-[var(--border-subtle)]">
              <div
                className={`h-full transition-all duration-300 ${
                  exhausted
                    ? 'bg-[var(--status-critical)]'
                    : remaining <= 3
                    ? 'bg-[var(--status-warning)]'
                    : 'bg-[var(--primary-orange)]'
                }`}
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        )}
      </section>
    );
  }

  // Verified registered user view: 4 independent per-capability balances
  const capLimit = quota.perCapabilityLimit ?? 5;
  const activeRemaining = activeCapability ? quota.balances[activeCapability] : null;
  const activeExhausted = activeRemaining !== null && activeRemaining <= 0;

  return (
    <section
      aria-label="Account Investigation Credits"
      className={`rounded-2xl border p-4 sm:p-5 space-y-3 shadow-sm ${
        activeExhausted
          ? 'border-[var(--status-warning-border)] bg-[var(--status-warning-bg)]'
          : 'border-[var(--border)] bg-[var(--card-bg)]'
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5">
        <div className="flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
          <ShieldCheck className="h-4 w-4 text-[var(--accent-cyan)] shrink-0" />
          <span>
            Verified Account Credits &middot; {quota.totalRemaining} Total Remaining
          </span>
        </div>
        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
          Independent per-tool balance (non-renewing)
        </span>
      </div>

      {activeExhausted && activeCapability && (
        <div
          role="alert"
          className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] px-3.5 py-2.5 text-xs text-[var(--status-critical)] flex items-start gap-2"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>
            <strong>{CAPABILITY_LABELS[activeCapability]} credits exhausted (0 / {capLimit}).</strong>{' '}
            Your remaining balances in other capabilities remain active and unaffected.
          </span>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        {CAPABILITY_ITEMS.map((item) => {
          const Icon = item.icon;
          const rem = quota.balances[item.key] ?? 0;
          const isCurrent = activeCapability === item.key;
          const isZero = rem <= 0;

          return (
            <Link
              key={item.key}
              href={item.href}
              className={`rounded-xl border p-2.5 transition-colors flex items-center justify-between gap-2 ${
                isCurrent
                  ? 'border-[var(--primary-orange)]/60 bg-[var(--surface-soft-orange)]'
                  : 'border-[var(--border)] bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40'
              }`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <Icon
                  className={`h-3.5 w-3.5 shrink-0 ${
                    isZero
                      ? 'text-[var(--status-critical)]'
                      : isCurrent
                      ? 'text-[var(--primary-orange)]'
                      : 'text-[var(--accent-cyan)]'
                  }`}
                />
                <span className="text-[11px] font-medium text-[var(--foreground)] truncate">
                  {compact ? item.shortLabel : item.label}
                </span>
              </div>
              <span
                className={`font-mono text-xs font-bold tabular-nums shrink-0 ${
                  isZero
                    ? 'text-[var(--status-critical)]'
                    : rem <= 1
                    ? 'text-[var(--status-warning)]'
                    : 'text-[var(--foreground)]'
                }`}
              >
                {rem}/{capLimit}
              </span>
            </Link>
          );
        })}
      </div>

      {!compact && (
        <p className="text-[11px] text-[var(--muted-foreground)]">
          Account plan: <span className="font-mono text-[var(--foreground-secondary)]">Standard Free</span> &middot; Additional referral bonuses and expanded plans will be introduced in a future update.
        </p>
      )}
    </section>
  );
}
