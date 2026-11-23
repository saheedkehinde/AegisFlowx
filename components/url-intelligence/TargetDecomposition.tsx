'use client';

import React, { useState } from 'react';
import { Layers, Copy, Check, Lock, Globe, Server, AlertTriangle, ArrowRight, CornerDownRight } from 'lucide-react';
import { UrlComponents } from '@/lib/url-investigation/types';
import { RedirectAnalysisResult } from '@/lib/url-investigation/redirect-resolver';

interface TargetDecompositionProps {
  urlComponents: UrlComponents;
  redirectResult?: RedirectAnalysisResult;
}

export default function TargetDecomposition({ urlComponents, redirectResult }: TargetDecompositionProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleCopy = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 1800);
  };

  return (
    <section
      aria-label="Target Structural Decomposition and Redirect Analysis"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-5"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
            <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Structural URL Decomposition &amp; Redirect Chain</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            RFC 3986 parse decomposition, safe parameter unwrapping, and multi-hop trace.
          </p>
        </div>
        <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
          Canonical Representation
        </span>
      </div>

      {/* Redirect Analysis Section */}
      {redirectResult && (
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-3 text-xs font-mono">
          <div className="flex items-center justify-between text-[11px] font-bold text-[var(--foreground)] border-b border-[var(--border-subtle)] pb-2">
            <span>Safe Redirect Pipeline Analysis</span>
            <span className={redirectResult.isRedirect ? 'text-[var(--primary-orange)]' : 'text-[var(--status-success)]'}>
              {redirectResult.isRedirect ? 'Redirect Chain Active' : 'Direct Navigation'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Original Submitted URL:</span>
              <div className="rounded bg-[var(--background)] p-2 text-[var(--foreground)] truncate border border-[var(--border-subtle)]">
                {redirectResult.originalUrl}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Decoded Destination:</span>
              <div className="rounded bg-[var(--background)] p-2 text-[var(--foreground)] truncate border border-[var(--border-subtle)]">
                {redirectResult.decodedDestination || 'None (No redirect parameter)'}
              </div>
            </div>
          </div>

          {redirectResult.redirectChain && redirectResult.redirectChain.length > 0 && (
            <div className="space-y-1.5 pt-1">
              <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Redirect Hop Sequence:</span>
              <div className="space-y-1.5">
                {redirectResult.redirectChain.map((hop, idx) => (
                  <div key={idx} className="flex items-center gap-2 bg-[var(--background)] p-2 rounded border border-[var(--border-subtle)] text-[11px]">
                    <span className="font-bold text-[var(--primary-orange)] shrink-0">#{hop.hopNumber}</span>
                    <CornerDownRight className="h-3 w-3 text-[var(--muted-foreground)] shrink-0" />
                    <span className="truncate text-[var(--foreground)] flex-1" title={hop.url}>{hop.url}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-interactive)] text-[var(--muted-foreground)] shrink-0">
                      {hop.redirectType} {hop.status ? `(${hop.status})` : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-1 pt-1">
            <span className="text-[10px] text-[var(--muted-foreground)] uppercase">Final Resolved Destination:</span>
            <div className="rounded bg-[var(--background)] p-2 text-[var(--foreground)] truncate border border-[var(--border-subtle)] font-bold text-[var(--primary-orange)]">
              {redirectResult.finalDestination}
            </div>
          </div>
        </div>
      )}

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
