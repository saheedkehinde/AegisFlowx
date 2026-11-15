'use client';

import React, { useState } from 'react';
import { Layers, Copy, Check, Lock, Globe, Server, AlertTriangle } from 'lucide-react';
import { UrlComponents } from '@/lib/url-investigation/types';

interface TargetDecompositionProps {
  urlComponents: UrlComponents;
}

export default function TargetDecomposition({ urlComponents }: TargetDecompositionProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleCopy = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 1800);
  };

  return (
    <section
      aria-label="Target Structural Decomposition"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Structural URL Decomposition</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Technical element extraction formatted per RFC 3986 standards.
          </p>
        </div>
        <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
          Canonical Representation
        </span>
      </div>

      {/* Structured Fields Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
        {/* Scheme */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between">
          <span className="text-[var(--muted-foreground)]">Scheme:</span>
          <span className="text-[var(--foreground)] font-bold">{urlComponents.protocol}</span>
        </div>

        {/* Port */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between">
          <span className="text-[var(--muted-foreground)]">Port:</span>
          <span className="text-[var(--foreground)]">
            {urlComponents.port ? urlComponents.port : 'Standard (443 / 80)'}
          </span>
        </div>

        {/* Hostname */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between gap-2 col-span-1 md:col-span-2">
          <span className="text-[var(--muted-foreground)] shrink-0">Hostname:</span>
          <div className="flex items-center gap-2 min-w-0">
            <span
              className="text-[var(--foreground)] font-bold truncate max-w-[280px] sm:max-w-[420px]"
              title={urlComponents.hostname}
            >
              {urlComponents.hostname}
            </span>
            <button
              type="button"
              onClick={() => handleCopy(urlComponents.hostname, 'hostname')}
              className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer shrink-0"
              title="Copy Hostname"
            >
              {copiedField === 'hostname' ? (
                <Check className="h-3.5 w-3.5 text-[var(--status-success)]" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        </div>

        {/* Registerable Domain */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between gap-2">
          <span className="text-[var(--muted-foreground)] shrink-0">Domain:</span>
          <span className="text-[var(--foreground)] font-bold truncate">
            {urlComponents.domain || 'N/A'}
          </span>
        </div>

        {/* Subdomain Characteristics */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between gap-2">
          <span className="text-[var(--muted-foreground)] shrink-0">Hosting Type:</span>
          <span className="text-[var(--foreground)] truncate">
            {urlComponents.isFreeHostingSubdomain
              ? 'Free Cloud Subdomain'
              : urlComponents.isShortenedUrl
              ? 'Known URL Shortener'
              : 'Registered Domain'}
          </span>
        </div>

        {/* Pathname */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between gap-2 col-span-1 md:col-span-2">
          <span className="text-[var(--muted-foreground)] shrink-0">Path:</span>
          <span
            className="text-[var(--foreground)] truncate max-w-[280px] sm:max-w-[440px]"
            title={urlComponents.pathname}
          >
            {urlComponents.pathname || '/'}
          </span>
        </div>

        {/* Defanged Display URL */}
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 flex items-center justify-between gap-2 col-span-1 md:col-span-2">
          <span className="text-[var(--muted-foreground)] shrink-0">Defanged Target:</span>
          <div className="flex items-center gap-2 min-w-0">
            <span
              className="text-[var(--foreground)] font-bold truncate max-w-[260px] sm:max-w-[420px]"
              title={urlComponents.displayUrl}
            >
              {urlComponents.displayUrl}
            </span>
            <button
              type="button"
              onClick={() => handleCopy(urlComponents.displayUrl, 'displayUrl')}
              className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer shrink-0"
              title="Copy Defanged URL"
            >
              {copiedField === 'displayUrl' ? (
                <Check className="h-3.5 w-3.5 text-[var(--status-success)]" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Sensitive Credentials Redacted Callout */}
      {urlComponents.redactedParamsCount > 0 && (
        <div className="rounded-xl border border-[var(--accent-amber)]/30 bg-[var(--accent-amber)]/5 p-3.5 text-xs flex items-center gap-2.5">
          <Lock className="h-4 w-4 text-[var(--accent-amber)] shrink-0" />
          <span className="text-[var(--foreground)]">
            <strong className="font-semibold text-[var(--accent-amber)]">
              Privacy Safeguard Active:
            </strong>{' '}
            {urlComponents.redactedParamsCount} sensitive parameter(s) (such as tokens, session keys,
            or password fragments) were masked prior to logging or database queries.
          </span>
        </div>
      )}
    </section>
  );
}
