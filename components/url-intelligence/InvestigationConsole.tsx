'use client';

import React from 'react';
import { Search, Globe, Shield, RefreshCw, XCircle, AlertCircle } from 'lucide-react';

interface InvestigationConsoleProps {
  url: string;
  setUrl: (url: string) => void;
  isLoading: boolean;
  onInvestigate: (overrideUrl?: string) => void;
  onClear: () => void;
  error: string | null;
}

export const SAMPLE_TARGETS = [
  {
    label: 'Credential Harvester Subdomain',
    category: 'Spoofing Pattern',
    url: 'https://security-verify.chase.com.account-update.example.com/login?token=SESS_991823&auth=active',
    hint: 'Homoglyph & subdomain chaining with sensitive credential parameters',
  },
  {
    label: 'Free Cloud Host Spoof',
    category: 'Hosting Anomaly',
    url: 'https://microsoft-login-verification.web.app/verify/index.html',
    hint: 'Free cloud platform abuse with login keywords in path',
  },
  {
    label: 'Obfuscated IP Literal Host',
    category: 'IP Hostname',
    url: 'http://198.51.100.45:8080/payload.bin',
    hint: 'RFC 5737 documentation IP with non-standard high port',
  },
  {
    label: 'Benign Canonical Reference',
    category: 'Standard Web Target',
    url: 'https://example.com/security/advisory-2026.html',
    hint: 'Clean RFC 2606 authoritative domain with valid structure',
  },
];

export default function InvestigationConsole({
  url,
  setUrl,
  isLoading,
  onInvestigate,
  onClear,
  error,
}: InvestigationConsoleProps) {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isLoading) return;
    onInvestigate();
  };

  return (
    <div className="space-y-4">
      {/* Primary Input Container */}
      <form
        onSubmit={handleSubmit}
        className="relative rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-3 sm:p-4 shadow-sm transition-all focus-within:border-[var(--primary-orange)] focus-within:ring-1 focus-within:ring-[var(--primary-orange)]/40"
      >
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          {/* URL Input */}
          <div className="relative flex-1 flex items-center min-w-0">
            <Globe className="absolute left-3.5 h-4 w-4 text-[var(--muted-foreground)] shrink-0 pointer-events-none" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter target URL or domain (e.g. https://example.com/login?token=abc)..."
              disabled={isLoading}
              className="w-full pl-10 pr-10 py-2.5 text-xs sm:text-sm font-mono bg-transparent text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none disabled:opacity-50"
              aria-label="Target URL for investigation"
            />
            {url && !isLoading && (
              <button
                type="button"
                onClick={onClear}
                className="absolute right-3 p-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer"
                title="Clear input"
              >
                <XCircle className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="submit"
              disabled={!url.trim() || isLoading}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-orange-hover)] text-white text-xs sm:text-sm font-bold shadow-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin motion-reduce:animate-none" />
                  <span>Scanning Target...</span>
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  <span>Investigate Destination</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Error Banner */}
      {error && (
        <div className="rounded-xl border border-[var(--status-critical)]/40 bg-[var(--status-critical-bg)] p-3.5 text-xs text-[var(--status-critical)] flex items-start gap-2.5 shadow-sm">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <div className="space-y-0.5 flex-1">
            <strong className="font-bold">Investigation Rejected:</strong>
            <p className="text-[11px] leading-relaxed opacity-90">{error}</p>
          </div>
        </div>
      )}

      {/* Synthetic Demonstration Quick-Picks (Zero-Pill Architecture) */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] text-[var(--foreground-secondary)] px-1">
          <span className="font-semibold flex items-center gap-1.5">
            <Shield className="h-3 w-3 text-[var(--primary-orange)]" />
            <span>Synthetic Demonstration Targets</span>
          </span>
          <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
            RFC 2606 &amp; 5737 Safe Telemetry
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {SAMPLE_TARGETS.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              disabled={isLoading}
              onClick={() => {
                setUrl(sample.url);
                onInvestigate(sample.url);
              }}
              className="text-left rounded-xl border border-[var(--border)] bg-[var(--card-bg)] hover:bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/50 p-3 space-y-1 transition-all cursor-pointer group disabled:opacity-50 disabled:cursor-not-allowed shadow-xs"
            >
              <div className="flex items-center justify-between text-[10px] font-mono">
                <span className="text-[var(--primary-orange)] font-bold group-hover:underline">
                  {sample.category}
                </span>
                <span className="text-[var(--muted-foreground)]">#{idx + 1}</span>
              </div>
              <div className="text-xs font-semibold text-[var(--foreground)] truncate">
                {sample.label}
              </div>
              <div className="text-[10px] text-[var(--muted-foreground)] line-clamp-1">
                {sample.hint}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
