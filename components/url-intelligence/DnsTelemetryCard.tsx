'use client';

import React from 'react';
import { Server, Globe, Mail, ShieldAlert, CheckCircle2, Info } from 'lucide-react';
import { DomainDnsIntelligence } from '@/lib/fact-checker/types';

interface DnsTelemetryCardProps {
  dns: DomainDnsIntelligence | null;
}

export default function DnsTelemetryCard({ dns }: DnsTelemetryCardProps) {
  if (!dns) {
    return (
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-3">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <Server className="h-4 w-4 text-[var(--accent-cyan)]" />
            <span>DNS &amp; Routing Telemetry</span>
          </h3>
          <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
            Resolution Unavailable
          </span>
        </div>
        <p className="text-xs text-[var(--muted-foreground)]">
          Live DNS resolution telemetry was not returned or could not be determined for this destination.
        </p>
      </div>
    );
  }

  const hasIps = dns.ipAddresses && dns.ipAddresses.length > 0;

  return (
    <section
      aria-label="DNS and Network Routing Telemetry"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <Server className="h-4 w-4 text-[var(--accent-cyan)]" />
            <span>DNS &amp; Network Routing Telemetry</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Zone resolution and authoritative mail exchanger discovery.
          </p>
        </div>
        <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
          Live Resolver Telemetry
        </span>
      </div>

      {/* Grid of Key DNS Dimensions */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        {/* Resolved IP Addresses */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
          <div className="flex items-center justify-between text-[10px] text-[var(--muted-foreground)] uppercase">
            <span>A / AAAA Records</span>
            <Globe className="h-3.5 w-3.5 text-[var(--accent-cyan)]" />
          </div>
          <div className="text-[var(--foreground)] font-bold truncate" title={hasIps ? dns.ipAddresses.join(', ') : 'None'}>
            {hasIps ? dns.ipAddresses.join(', ') : 'No IP records resolved'}
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)]">
            {hasIps ? `${dns.ipAddresses.length} address(es) returned` : 'Zone lookup empty'}
          </div>
        </div>

        {/* Mail Exchanger Records */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
          <div className="flex items-center justify-between text-[10px] text-[var(--muted-foreground)] uppercase">
            <span>Mail Exchanger (MX)</span>
            <Mail className="h-3.5 w-3.5 text-[var(--accent-amber)]" />
          </div>
          <div className="text-[var(--foreground)] font-bold truncate">
            {dns.hasMailServers
              ? `${dns.mxRecordsCount} MX host(s) configured`
              : 'No MX records declared'}
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)]">
            {dns.hasMailServers ? 'Operational mail routing' : 'Domain does not receive mail'}
          </div>
        </div>

        {/* Infrastructure Zone Status */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
          <div className="flex items-center justify-between text-[10px] text-[var(--muted-foreground)] uppercase">
            <span>Zone State</span>
            {dns.isSuspiciousOrParked ? (
              <ShieldAlert className="h-3.5 w-3.5 text-[var(--status-critical)]" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5 text-[var(--status-success)]" />
            )}
          </div>
          <div
            className={`font-bold truncate ${
              dns.isSuspiciousOrParked ? 'text-[var(--status-critical)]' : 'text-[var(--status-success)]'
            }`}
          >
            {dns.isSuspiciousOrParked ? 'Anomalous / Parked Domain' : 'Active Routing Profile'}
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)]">
            {dns.isSuspiciousOrParked ? 'Absence of canonical host records' : 'Functional authoritative delegation'}
          </div>
        </div>
      </div>

      {/* Resolver Notes */}
      {dns.notes && (
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 text-xs text-[var(--foreground-secondary)] font-mono">
          <span className="text-[var(--foreground)] font-semibold">Resolver Notes:</span> {dns.notes}
        </div>
      )}

      {/* Heuristic Caveat Banner */}
      <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] p-3 text-[11px] text-[var(--muted-foreground)] flex items-start gap-2">
        <Info className="h-3.5 w-3.5 text-[var(--accent-cyan)] shrink-0 mt-0.5" />
        <span>
          <strong className="text-[var(--foreground)]">Telemetry Caution:</strong> Missing MX records or specialized hosting infrastructure alone do not prove malicious intent. DNS telemetry provides structural context to evaluate alongside behavioral signals.
        </span>
      </div>
    </section>
  );
}
