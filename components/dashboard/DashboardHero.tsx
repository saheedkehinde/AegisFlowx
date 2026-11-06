'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  Link2,
  Database,
  GraduationCap,
  ArrowRight,
  ShieldCheck,
  Lock,
} from 'lucide-react';
import type { User } from '@supabase/supabase-js';

interface DashboardHeroProps {
  user: User | null;
  analystName: string;
  savedCount: number | null;
  sessionCount: number;
}

export default function DashboardHero({
  user,
  analystName,
  savedCount,
  sessionCount,
}: DashboardHeroProps) {
  return (
    <section
      aria-label="Command Centre Welcome and Operations Header"
      className="relative overflow-hidden rounded-2xl border border-[var(--border)] bg-gradient-to-br from-[var(--surface-elevated)] via-[var(--surface)] to-[var(--background-secondary)] p-6 sm:p-8 lg:p-9 shadow-md transition-colors"
    >
      {/* Subtle cyber grid and ambient glow effects */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 cyber-grid opacity-30"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-20 -top-20 h-80 w-80 rounded-full bg-[var(--primary-orange-glow)] blur-3xl opacity-50"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-20 -bottom-20 h-64 w-64 rounded-full bg-[var(--accent-cyan-subtle)] blur-3xl opacity-30"
      />

      {/* Decorative technical crosshair / radar geometry */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden xl:block opacity-10 text-[var(--primary-orange)]"
      >
        <svg width="240" height="240" viewBox="0 0 240 240" fill="none" stroke="currentColor">
          <circle cx="120" cy="120" r="110" strokeWidth="1" strokeDasharray="4 4" />
          <circle cx="120" cy="120" r="75" strokeWidth="1" />
          <circle cx="120" cy="120" r="40" strokeWidth="1" strokeDasharray="2 4" />
          <circle cx="120" cy="120" r="5" fill="currentColor" />
          <line x1="120" y1="0" x2="120" y2="240" strokeWidth="0.75" />
          <line x1="0" y1="120" x2="240" y2="120" strokeWidth="0.75" />
        </svg>
      </div>

      <div className="relative z-10 max-w-3xl space-y-5">
        {/* Domain Kicker and Operational State */}
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="inline-flex items-center gap-1.5 font-medium text-[var(--foreground-secondary)]">
            <span className="h-2 w-2 rounded-full bg-[var(--primary-orange)] animate-pulse" />
            <span className="font-mono uppercase tracking-wider text-[11px] text-[var(--foreground)]">
              Midnight Intelligence Console
            </span>
          </div>

          <span className="text-[var(--border-strong)]" aria-hidden="true">
            /
          </span>

          {user ? (
            <div className="inline-flex items-center gap-1.5 text-[11px] font-mono text-[var(--status-success)]">
              <Lock className="h-3.5 w-3.5" />
              <span>Cloud Vault &middot; RLS Protected</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 text-[11px] font-mono text-[var(--status-warning)]">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-warning)]" />
              <span>Guest Analyst Session &middot; Volatile RAM</span>
            </div>
          )}
        </div>

        {/* Headline & Contextual Greeting */}
        <div className="space-y-2.5">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-[var(--foreground)] leading-tight">
            {user ? (
              <>
                Command Centre: Welcome back,{' '}
                <span className="text-[var(--primary-orange)] font-bold">{analystName}</span>.
              </>
            ) : (
              <>Autonomous Cybersecurity Intelligence Command Centre</>
            )}
          </h1>

          <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed max-w-2xl">
            AegisFlow delivers automated behavioral threat triage, multimodal OCR document inspection,
            SSRF-hardened link screening, and evidence-grounded claim analysis engineered to neutralize
            social engineering before compromise.
          </p>
        </div>

        {/* Primary and Secondary Action Bar */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] px-5 py-3 text-xs sm:text-sm font-semibold shadow-md shadow-[var(--primary-orange-glow)] transition-all duration-150 cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px]"
          >
            <ShieldAlert className="h-4 w-4" />
            <span>Start Threat Investigation</span>
            <ArrowRight className="h-4 w-4" />
          </Link>

          <Link
            href="/url-investigation"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40 px-4 py-3 text-xs sm:text-sm font-medium text-[var(--foreground)] transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px] shadow-sm"
          >
            <Link2 className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>URL Intelligence</span>
          </Link>

          <Link
            href="/investigations"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-3 text-xs sm:text-sm font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px] shadow-sm"
          >
            <Database className="h-4 w-4 text-[var(--accent-cyan)]" />
            <span>
              Investigation Vault {user && savedCount !== null ? `(${savedCount})` : ''}
            </span>
          </Link>

          <Link
            href="/academy"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-3 text-xs sm:text-sm font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px] shadow-sm"
          >
            <GraduationCap className="h-4 w-4 text-[var(--accent-violet)]" />
            <span>Security Academy</span>
          </Link>
        </div>
      </div>
    </section>
  );
}
