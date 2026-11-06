'use client';

import React from 'react';
import Link from 'next/link';
import { Sliders, ShieldCheck, Cpu, Database, Network, Server, ArrowRight } from 'lucide-react';

interface PlatformTelemetryProps {
  isAuthenticated: boolean;
}

export default function PlatformTelemetry({ isAuthenticated }: PlatformTelemetryProps) {
  return (
    <section
      aria-label="Configured Architecture and Infrastructure Baseline"
      className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6 shadow-sm space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-[var(--foreground-secondary)]" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)]">
              Configured Architecture &amp; Integration Baseline
            </h2>
          </div>
          <p className="text-xs text-[var(--foreground-secondary)]">
            Static architectural parameters. Live API latency and upstream provider reachability can be tested on the Diagnostics console.
          </p>
        </div>

        <Link
          href="/settings?tab=diagnostics"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40 px-3 py-1.5 text-xs font-medium text-[var(--primary-orange)] transition-colors self-start shrink-0"
        >
          <Sliders className="h-3.5 w-3.5" />
          <span>Run Live Health Checks</span>
          <ArrowRight className="h-3 w-3" />
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        {/* Card 1: AI Inference Engine */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex flex-col justify-between space-y-2">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
              <span>Inference Engine</span>
              <Cpu className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
            </div>
            <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
              Qwen3-VL-8B-Instruct
            </span>
            <span className="text-[11px] text-[var(--foreground-secondary)] block truncate">
              Provider: Featherless AI Gateway
            </span>
          </div>
          <div className="pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)]">
            <span>Configured Model Baseline</span>
          </div>
        </div>

        {/* Card 2: Persistence Architecture */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex flex-col justify-between space-y-2">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
              <span>Storage Architecture</span>
              <Database className="h-3.5 w-3.5 text-[var(--accent-cyan)]" />
            </div>
            <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
              {isAuthenticated ? 'Supabase PostgreSQL' : 'Volatile Client RAM'}
            </span>
            <span className="text-[11px] text-[var(--foreground-secondary)] block truncate">
              {isAuthenticated ? 'Row Level Security Active' : 'Session Memory Scope'}
            </span>
          </div>
          <div className="pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)]">
            <span>{isAuthenticated ? 'Cloud Vault Storage' : 'Zero-Retention Mode'}</span>
          </div>
        </div>

        {/* Card 3: Threat Feeds */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex flex-col justify-between space-y-2">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
              <span>Threat Intelligence</span>
              <Network className="h-3.5 w-3.5 text-[var(--accent-amber)]" />
            </div>
            <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
              URLhaus &middot; Serper.dev
            </span>
            <span className="text-[11px] text-[var(--foreground-secondary)] block truncate">
              abuse.ch Database &amp; Search API
            </span>
          </div>
          <div className="pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)]">
            <span>Configured External Feeds</span>
          </div>
        </div>

        {/* Card 4: SSRF Controls */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex flex-col justify-between space-y-2">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
              <span>Network Defense</span>
              <ShieldCheck className="h-3.5 w-3.5 text-[var(--status-success)]" />
            </div>
            <span className="font-mono text-xs font-semibold text-[var(--foreground)] block truncate">
              SSRF &amp; Metadata Shield
            </span>
            <span className="text-[11px] text-[var(--foreground-secondary)] block truncate">
              RFC-1918, 169.254.x.x, IPv6 Filter
            </span>
          </div>
          <div className="pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)]">
            <span>Enforced on Outbound Lookups</span>
          </div>
        </div>
      </div>
    </section>
  );
}
