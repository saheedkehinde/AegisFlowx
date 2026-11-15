'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  UserCheck,
  Building,
  Terminal,
  ExternalLink,
  BookOpen,
  AlertCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { AudienceRecommendations, ResearchSource } from '@/lib/fact-checker/types';

interface ResponsePlaybookProps {
  recommendations: AudienceRecommendations;
  webEvidence?: ResearchSource[];
  limitations?: string[];
  modelUsed?: string;
}

export default function ResponsePlaybook({
  recommendations,
  webEvidence = [],
  limitations = [],
  modelUsed,
}: ResponsePlaybookProps) {
  const [activeTab, setActiveTab] = useState<'individuals' | 'security' | 'organizations'>('individuals');
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 1800);
  };

  const currentActions =
    activeTab === 'individuals'
      ? recommendations.forIndividuals || []
      : activeTab === 'security'
      ? recommendations.forSecurityTeams || []
      : recommendations.forOrganizations || [];

  return (
    <div className="space-y-6">
      {/* Response Playbook Section */}
      <section
        aria-label="Actionable Mitigation Playbook"
        className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
          <div>
            <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[var(--primary-orange)]" />
              <span>Mitigation &amp; Incident Playbook</span>
            </h3>
            <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
              Audience-specific triage procedures, containment recommendations, and defensive steps.
            </p>
          </div>
          <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
            Response Guidance
          </span>
        </div>

        {/* Tab Controls (Zero-pill segmented bar) */}
        <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2 overflow-x-auto text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('individuals')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium cursor-pointer transition-colors border ${
              activeTab === 'individuals'
                ? 'border-[var(--primary-orange)]/40 bg-[var(--surface-active)] text-[var(--primary-orange)] font-bold'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]'
            }`}
          >
            <UserCheck className="h-3.5 w-3.5" />
            <span>Personal &amp; User Safety</span>
            <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
              ({recommendations.forIndividuals?.length || 0})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('security')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium cursor-pointer transition-colors border ${
              activeTab === 'security'
                ? 'border-[var(--accent-cyan)]/40 bg-[var(--surface-active)] text-[var(--accent-cyan)] font-bold'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]'
            }`}
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>SOC &amp; Incident Response</span>
            <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
              ({recommendations.forSecurityTeams?.length || 0})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('organizations')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium cursor-pointer transition-colors border ${
              activeTab === 'organizations'
                ? 'border-[var(--accent-amber)]/40 bg-[var(--surface-active)] text-[var(--accent-amber)] font-bold'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]'
            }`}
          >
            <Building className="h-3.5 w-3.5" />
            <span>Enterprise Policy</span>
            <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
              ({recommendations.forOrganizations?.length || 0})
            </span>
          </button>
        </div>

        {/* Action Steps List */}
        <div className="space-y-2.5 pt-1">
          {currentActions.length > 0 ? (
            currentActions.map((action, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex items-start gap-3 text-xs leading-relaxed"
              >
                <span className="font-mono text-[10px] font-bold text-[var(--primary-orange)] shrink-0 mt-0.5 w-5 h-5 rounded-full bg-[var(--surface-active)] border border-[var(--border)] flex items-center justify-center">
                  {idx + 1}
                </span>
                <span className="text-[var(--foreground)]">{action}</span>
              </div>
            ))
          ) : (
            <p className="text-xs text-[var(--muted-foreground)] py-2">
              No specific recommendations generated for this tier.
            </p>
          )}
        </div>
      </section>

      {/* Corroborating Web Evidence (if available) */}
      {webEvidence && webEvidence.length > 0 && (
        <section
          aria-label="Corroborating Web Evidence and OSINT"
          className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm space-y-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
            <div>
              <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] flex items-center gap-2">
                <BookOpen className="h-4 w-4 text-[var(--accent-cyan)]" />
                <span>Corroborating OSINT &amp; Web Evidence</span>
              </h3>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Public research references and contextual reports identified during investigation.
              </p>
            </div>
            <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
              {webEvidence.length} source(s)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {webEvidence.map((source, idx) => (
              <div
                key={source.id || idx}
                className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 flex flex-col justify-between space-y-2.5"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="font-bold text-[var(--foreground)] line-clamp-1">
                      {source.title || 'Untitled Evidence Reference'}
                    </h4>
                    <span className="text-[10px] font-mono text-[var(--accent-cyan)] shrink-0">
                      {source.domain}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--foreground-secondary)] mt-1 line-clamp-2 leading-relaxed">
                    {source.snippet}
                  </p>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--muted-foreground)]">
                  <span>{source.publisher || source.sourceType || 'OSINT'}</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(source.url)}
                    className="flex items-center gap-1 hover:text-[var(--foreground)] transition-colors cursor-pointer"
                    title="Copy Defanged Source URL"
                  >
                    {copiedUrl === source.url ? (
                      <>
                        <Check className="h-3 w-3 text-[var(--status-success)]" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy URL</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Investigation Boundaries & Limitations */}
      <section
        aria-label="Investigation Boundaries and Scope"
        className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)]/60 p-4 sm:p-5 text-xs text-[var(--foreground-secondary)] space-y-2.5"
      >
        <div className="flex items-center gap-2 text-[var(--foreground)] font-bold text-xs">
          <AlertCircle className="h-4 w-4 text-[var(--primary-orange)]" />
          <span>Forensic Scope &amp; Investigation Boundaries</span>
        </div>

        <ul className="space-y-1.5 text-[11px] leading-relaxed list-disc list-inside text-[var(--muted-foreground)]">
          {limitations && limitations.length > 0 ? (
            limitations.map((lim, idx) => (
              <li key={idx}>
                <span className="text-[var(--foreground-secondary)]">{lim}</span>
              </li>
            ))
          ) : (
            <>
              <li>
                <span className="text-[var(--foreground-secondary)]">
                  Passive OSINT inspection only. AegisFlow does not execute arbitrary code or submit payloads to live target infrastructure.
                </span>
              </li>
              <li>
                <span className="text-[var(--foreground-secondary)]">
                  Community feed coverage (e.g. URLhaus) reflects confirmed malware distributions and may not capture zero-hour credential harvests.
                </span>
              </li>
            </>
          )}
        </ul>

        {modelUsed && (
          <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[10px] font-mono text-[var(--muted-foreground)]">
            <span>
              Synthesis Engine:{' '}
              {/qwen|featherless|gemini|serper/i.test(modelUsed)
                ? 'Aegis AI URL Intelligence + Threat Feeds + Authoritative DNS'
                : modelUsed}
            </span>
            <span>AegisFlow Telemetry</span>
          </div>
        )}
      </section>
    </div>
  );
}
