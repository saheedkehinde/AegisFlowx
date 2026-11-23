'use client';

import React, { useState } from 'react';
import {
  Globe,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  ShieldAlert,
  Server,
  Building,
  UserCheck,
  Shield,
  Layers,
  FileText,
  MessageSquare,
  AlertOctagon,
  ChevronDown,
  ChevronUp,
  Info,
  Landmark,
} from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';
import {
  FactCheckReport,
  FactualClaim,
  SourceProvenance,
  SourceRelevanceGrade,
} from '@/lib/fact-checker/types';

interface FactCheckCardProps {
  report: FactCheckReport;
  onReset?: () => void;
}

export default function FactCheckCard({ report, onReset }: FactCheckCardProps) {
  const [activeAudienceTab, setActiveAudienceTab] = useState<'individual' | 'org' | 'finance' | 'security'>(
    report.paymentChangeDetection?.detected && report.recommendations.forFinanceTeams?.length
      ? 'finance'
      : 'individual'
  );
  const [expandedSourceId, setExpandedSourceId] = useState<string | null>(null);

  const getVerdictBadge = (verdict: FactualClaim['verdict']) => {
    switch (verdict) {
      case 'supported':
        return {
          label: 'Supported by Available Evidence',
          color: 'text-[var(--status-success)] bg-[var(--status-success-bg)] border-[var(--status-success-border)]',
          icon: CheckCircle2,
        };
      case 'contradicted':
        return {
          label: 'Contradicted by Available Evidence',
          color: 'text-[var(--status-critical)] bg-[var(--status-critical-bg)] border-[var(--status-critical-border)]',
          icon: XCircle,
        };
      case 'misleading':
        return {
          label: 'Misleading / Missing Context',
          color: 'text-[var(--status-warning)] bg-[var(--status-warning-bg)] border-[var(--status-warning-border)]',
          icon: AlertTriangle,
        };
      case 'unverified_suspicious':
        return {
          label: 'Suspicious / Not Independently Verified',
          color: 'text-[var(--status-uncertain)] bg-[var(--status-uncertain-bg)] border-[var(--status-uncertain-border)]',
          icon: ShieldAlert,
        };
      case 'no_verifiable_claim':
        return {
          label: 'No Independently Verifiable Claim Identified',
          color: 'text-[var(--accent-violet)] bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30',
          icon: MessageSquare,
        };
      case 'inconclusive':
      default:
        return {
          label: 'Inconclusive (Evidence Insufficient)',
          color: 'text-[var(--foreground-secondary)] bg-[var(--surface-interactive)] border-[var(--border)]',
          icon: HelpCircle,
        };
    }
  };

  const getProvenanceBadge = (provenance: SourceProvenance) => {
    switch (provenance) {
      case 'full_page_retrieved':
        return {
          label: 'Full Webpage Retrieved',
          color: 'text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30',
        };
      case 'encyclopedia':
        return {
          label: 'Official Encyclopedia',
          color: 'text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30',
        };
      case 'authoritative_dns':
        return {
          label: 'Authoritative DNS Telemetry',
          color: 'text-[var(--accent-violet)] bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30',
        };
      case 'threat_intelligence':
        return {
          label: 'Threat Feed Match',
          color: 'text-[var(--status-critical)] bg-[var(--status-critical-bg)] border-[var(--status-critical-border)]',
        };
      case 'page_retrieval_failed':
        return {
          label: 'Page Retrieval Failed (Snippet Only)',
          color: 'text-[var(--status-warning)] bg-[var(--status-warning-bg)] border-[var(--status-warning-border)]',
        };
      case 'cached_evidence':
        return {
          label: 'Cached Evidence Snapshot',
          color: 'text-[var(--accent-violet)] bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30',
        };
      case 'snippet_only':
      default:
        return {
          label: 'Search Snippet Only',
          color: 'text-[var(--foreground-secondary)] bg-[var(--surface-interactive)] border-[var(--border)]',
        };
    }
  };

  const getRelevanceBadge = (grade?: SourceRelevanceGrade) => {
    switch (grade) {
      case 'direct_evidence':
        return {
          label: 'Direct Evidence',
          color: 'text-[var(--status-success)] bg-[var(--status-success-bg)] border-[var(--status-success-border)]',
        };
      case 'supporting_guidance':
        return {
          label: 'Supporting Guidance',
          color: 'text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30',
        };
      case 'threat_or_dns_telemetry':
        return {
          label: 'Telemetry',
          color: 'text-[var(--accent-violet)] bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30',
        };
      case 'unrelated':
        return {
          label: 'Unrelated (Excluded)',
          color: 'text-[var(--muted-foreground)] bg-[var(--surface-interactive)] border-[var(--border)] line-through',
        };
      case 'indirect_or_weak':
      default:
        return {
          label: 'Platform Context',
          color: 'text-[var(--status-warning)] bg-[var(--status-warning-bg)] border-[var(--status-warning-border)]',
        };
    }
  };

  const status = report.searchProviderStatus?.researchStatus;

  return (
    <div className="space-y-6">
      {/* Top Fact-Checking Dossier Banner */}
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-7 shadow-[var(--shadow-sm)]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[var(--border-subtle)] pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] px-2.5 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] font-semibold">
                <Globe className="h-3 w-3" aria-hidden="true" />
                <span>Evidence-Based Web Research Dossier</span>
              </span>
              <span className="text-xs font-mono text-[var(--muted-foreground)] tabular-nums">
                {new Date(report.analyzedAt).toLocaleTimeString()}
              </span>

              {/* Research Execution Status Badge */}
              {status === 'live_research_completed' && (
                <span className="rounded-md bg-[var(--status-success-bg)] border border-[var(--status-success-border)] px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--status-success)]">
                  Live Research Completed
                </span>
              )}
              {status === 'completed_using_cached_evidence' && (
                <span className="rounded-md bg-[var(--accent-violet-subtle)] border border-[var(--accent-violet)]/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--accent-violet)]">
                  Pre-Cached Evidence
                </span>
              )}
              {status === 'quota_exhausted' && (
                <span className="rounded-md bg-[var(--status-warning-bg)] border border-[var(--status-warning-border)] px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--status-warning)]">
                  Quota Exhausted
                </span>
              )}
              {status === 'partially_completed' && (
                <span className="rounded-md bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--accent-cyan)]">
                  Request Limit Reached
                </span>
              )}
              {status === 'not_required' && (
                <span className="rounded-md bg-[var(--surface-interactive)] border border-[var(--border)] px-2 py-0.5 text-[10px] font-mono text-[var(--muted-foreground)]">
                  Web Search Not Required
                </span>
              )}

              {/* Research Engine Badge */}
              <span className="rounded-md bg-[var(--surface-interactive)] border border-[var(--border)] px-2 py-0.5 text-[10px] font-mono text-[var(--foreground-secondary)]">
                Engine:{' '}
                <strong className="text-[var(--accent-cyan)]">
                  {/serper|gemini|wikimedia|qwen|featherless/i.test(
                    report.searchProviderStatus?.providerName || report.searchProviderUsed || ''
                  )
                    ? 'Aegis AI Research Engine'
                    : report.searchProviderStatus?.providerName || report.searchProviderUsed || 'Aegis AI Research Engine'}
                </strong>
              </span>

              {/* Outbound count vs Cache hits */}
              {report.searchProviderStatus?.outboundSearchesExecuted !== undefined && (
                <span className="rounded-md bg-[var(--surface-interactive)] border border-[var(--border)] px-2 py-0.5 text-[10px] font-mono text-[var(--foreground-secondary)] tabular-nums">
                  Queries: <strong className="text-[var(--foreground)]">{report.searchProviderStatus.outboundSearchesExecuted}</strong> outbound
                  {report.searchProviderStatus.cacheHitsCount > 0 && (
                    <span>, <strong className="text-[var(--accent-cyan)]">{report.searchProviderStatus.cacheHitsCount}</strong> cached</span>
                  )}
                </span>
              )}

              {report.searchProviderStatus?.fullPageRetrievalActive && (
                <span className="rounded-md bg-[var(--status-success-bg)] border border-[var(--status-success-border)] px-2 py-0.5 text-[10px] font-mono font-semibold text-[var(--status-success)]">
                  Full-Page Content Retrieved
                </span>
              )}
            </div>

            <h3 className="mt-1 text-xl sm:text-2xl font-extrabold text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Evidence-Based Intelligence Report
            </h3>
            <p className="mt-2 text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed max-w-3xl">
              {report.executiveSummary}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row flex-wrap items-start sm:items-center gap-2 self-start lg:self-center shrink-0">
            <ThreatBadge
              level={report.threatSeverity}
              score={report.severityScore}
              showScore={true}
              size="md"
            />

            {report.assessmentStateLabel && (
              <span className="rounded-lg bg-[var(--surface-interactive)] border border-[var(--border)] px-3 py-1.5 text-xs font-mono text-[var(--foreground)]">
                Status: <strong>{report.assessmentStateLabel}</strong>
              </span>
            )}
            <span className="rounded-lg bg-[var(--surface-interactive)] border border-[var(--border)] px-3 py-1.5 text-xs font-mono text-[var(--accent-cyan)]">
              Confidence: <strong className="capitalize text-[var(--foreground)]">{report.confidenceLevel}</strong>
            </span>
            {(report.evidenceCoverage || report.evidenceSufficiency) && (
              <span className="rounded-lg bg-[var(--surface-interactive)] border border-[var(--border)] px-3 py-1.5 text-xs font-mono text-[var(--accent-cyan)]">
                Coverage: <strong className="capitalize text-[var(--foreground)]">{report.evidenceCoverage || report.evidenceSufficiency}</strong>
              </span>
            )}
            {onReset && (
              <button
                type="button"
                onClick={onReset}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-1.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
              >
                New Fact-Check
              </button>
            )}
          </div>
        </div>

        {/* Confidence Rationale Note */}
        {report.confidenceRationale && (
          <div className="mt-3 text-[11px] font-mono text-[var(--foreground-secondary)] flex items-start gap-1.5 bg-[var(--surface-interactive)] px-3 py-2 rounded-lg border border-[var(--border-subtle)]">
            <span className="text-[var(--accent-cyan)] font-semibold shrink-0">Confidence Rationale:</span>
            <span>{report.confidenceRationale}</span>
          </div>
        )}

        {/* Quota Exhaustion Alert */}
        {status === 'quota_exhausted' && (
          <div className="mt-4 rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3 text-xs text-[var(--foreground)] flex items-start gap-2.5">
            <AlertOctagon className="h-4 w-4 shrink-0 text-[var(--status-warning)] mt-0.5" aria-hidden="true" />
            <div>
              <strong className="font-semibold block text-[var(--status-warning)]">Live Web Search Allowance Reached</strong>
              <p className="mt-0.5 text-[var(--foreground-secondary)] leading-relaxed">
                External search query allowance has been reached for the current period. This investigation was completed using local threat intelligence, DNS telemetry, and Aegis AI heuristic evaluation. For critical inquiries, contact the institution through official verified channels directly.
              </p>
            </div>
          </div>
        )}

        {/* Rate limit warning */}
        {report.searchProviderStatus?.rateLimitEncountered && status !== 'quota_exhausted' && (
          <div className="mt-4 rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3 text-xs text-[var(--status-warning)] flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>External search rate limit reached. Analysis automatically utilized public registries and cached intelligence fallbacks.</span>
          </div>
        )}

        {/* Non-Public-Claim / Private Transactional / Conversational Communication Banner */}
        {!report.hasVerifiableClaims && (
          report.paymentChangeDetection?.detected ||
          report.threatSeverity === 'high' ||
          report.threatSeverity === 'medium' ? (
            <div className="mt-5 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-4 space-y-2">
              <div className="flex items-center gap-2 text-[var(--status-critical)] font-semibold text-xs">
                <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>
                  {report.paymentChangeDetection?.isActiveRedirectionRequest
                    ? 'Private Payment-Redirection / Business Email Compromise (BEC) Risk Detected'
                    : report.paymentChangeDetection?.isInformationalOnlyNotice
                    ? 'Unverified Bank-Account Change Notice (Private Transactional Communication)'
                    : `Direct Threat Assessment: ${report.threatAssessment?.primaryCategoryLabel || 'High-Risk Private Communication'}`}
                </span>
              </div>
              <p className="text-xs text-[var(--foreground)] leading-relaxed">
                Public web search was intentionally not executed because this message contains private bilateral or transactional instructions rather than publicly verifiable organizational announcements. Bypassed public search NEVER establishes legitimacy or safety.
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)]">
                Verification requirement: Do not release funds or update beneficiary bank records without independent out-of-band confirmation using a previously established trusted contact number.
              </p>
            </div>
          ) : report.primaryThreatCategory === 'ordinary_conversational' && report.threatSeverity === 'low' ? (
            <div className="mt-5 rounded-xl border border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] p-4 space-y-2">
              <div className="flex items-center gap-2 text-[var(--accent-violet)] font-semibold text-xs">
                <MessageSquare className="h-4 w-4" aria-hidden="true" />
                <span>Ordinary Conversational Communication (No Threat Indicators Observed)</span>
              </div>
              <p className="text-xs text-[var(--foreground)] leading-relaxed">
                This message contains polite greetings or routine conversational remarks without verifiable corporate claims, URLs, or financial directives. No external searches were executed.
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)]">
                Security note: Absence of threat indicators in short text does not verify sender identity; verify out-of-band if an unknown contact later introduces financial or credential requests.
              </p>
            </div>
          ) : (
            <div className="mt-5 rounded-xl border border-[var(--status-uncertain-border)] bg-[var(--status-uncertain-bg)] p-4 space-y-2">
              <div className="flex items-center gap-2 text-[var(--status-uncertain)] font-semibold text-xs">
                <HelpCircle className="h-4 w-4" aria-hidden="true" />
                <span>Insufficient Context / Unverified Private Fragment</span>
              </div>
              <p className="text-xs text-[var(--foreground)] leading-relaxed">
                This submission lacks public organizational entities, URLs, and sender authentication context. Public web search could not verify intent; treat unverified requests with caution.
              </p>
            </div>
          )
        )}

        {/* Separated 3-Dimension Security & Verification Assessment */}
        {report.threatAssessment && report.factualVerification && report.authenticityAssessment && (
          <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--primary-orange)]">
                1. Threat Assessment
              </span>
              <p className="text-xs font-bold text-[var(--foreground)]">
                {report.threatAssessment.primaryCategoryLabel}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {report.threatAssessment.summary}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--accent-cyan)]">
                2. Factual Verification
              </span>
              <p className="text-xs font-bold text-[var(--foreground)] capitalize">
                {report.factualVerification.status.replace(/_/g, ' ')}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {report.factualVerification.claimsSummary}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--accent-violet)]">
                3. Authenticity Assessment
              </span>
              <p className="text-xs font-bold text-[var(--foreground)] capitalize">
                {report.authenticityAssessment.status.replace(/_/g, ' ')}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {report.authenticityAssessment.summary}
              </p>
            </div>
          </div>
        )}

        {/* SECTION 1: CLAIMS IDENTIFIED & CROSS-EXAMINATION */}
        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
              <Layers className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
              <span className="tabular-nums">Extracted Claims &amp; Evidence Cross-Examination ({report.extractedClaims.length})</span>
            </h4>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Qualified evidence assessment</span>
          </div>

          <div className="space-y-3">
            {report.extractedClaims.map((claim) => {
              const badge = getVerdictBadge(claim.verdict);
              const VerdictIcon = badge.icon;

              return (
                <div
                  key={claim.id}
                  className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-3 hover:border-[var(--border)] transition-colors"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-[var(--foreground)] break-words flex-1">
                      &ldquo;{claim.claimText}&rdquo;
                    </span>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[10px] font-mono font-semibold shrink-0 ${badge.color}`}
                    >
                      <VerdictIcon className="h-3 w-3" aria-hidden="true" />
                      <span>{badge.label}</span>
                    </span>
                  </div>

                  {claim.evidenceNeeded && (
                    <div className="text-[11px] text-[var(--foreground-secondary)] font-mono flex items-start gap-1.5 bg-[var(--background-secondary)] p-2.5 rounded-lg border border-[var(--border-subtle)]">
                      <span className="text-[var(--accent-cyan)] font-semibold shrink-0">Verification Criteria:</span>
                      <span>{claim.evidenceNeeded}</span>
                    </div>
                  )}

                  <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed rounded-lg bg-[var(--background-secondary)]/60 px-3 py-2 border border-[var(--border-subtle)]">
                    {claim.verdictExplanation}
                  </p>

                  {/* Contradicting Evidence */}
                  {claim.contradictingEvidence.length > 0 && (
                    <div className="rounded-lg bg-[var(--status-critical-bg)] border border-[var(--status-critical-border)] p-3 text-xs space-y-1.5">
                      <span className="font-semibold text-[var(--status-critical)] flex items-center gap-1.5 text-[11px]">
                        <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        <span>Contradicting Evidence &amp; Public Advisories:</span>
                      </span>
                      <ul className="space-y-1 text-[var(--foreground)] text-[11px] list-disc list-inside">
                        {claim.contradictingEvidence.map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Supporting Evidence */}
                  {claim.supportingEvidence.length > 0 && (
                    <div className="rounded-lg bg-[var(--status-success-bg)] border border-[var(--status-success-border)] p-3 text-xs space-y-1.5">
                      <span className="font-semibold text-[var(--status-success)] flex items-center gap-1.5 text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        <span>Supporting Corroboration:</span>
                      </span>
                      <ul className="space-y-1 text-[var(--foreground)] text-[11px] list-disc list-inside">
                        {claim.supportingEvidence.map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Cited Source URLs for this claim */}
                  {claim.citedSourceUrls.length > 0 && (
                    <div className="pt-1 flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                      <span className="text-[var(--muted-foreground)]">Direct Sources:</span>
                      {claim.citedSourceUrls.map((cUrl, idx) => (
                        <a
                          key={idx}
                          href={cUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[var(--accent-cyan)] hover:underline bg-[var(--surface)] px-2 py-0.5 rounded border border-[var(--border-subtle)] truncate max-w-[220px]"
                        >
                          {cUrl}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* SECTION 1B: BEHAVIORAL THREAT INDICATORS */}
        {report.suspiciousIndicators && report.suspiciousIndicators.length > 0 && (
          <div className="mt-7 space-y-3 border-t border-[var(--border-subtle)] pt-6">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-[var(--status-warning)]" aria-hidden="true" />
                <span className="tabular-nums">Behavioral Threat Indicators &amp; Social Engineering Markers ({report.suspiciousIndicators.length})</span>
              </h4>
              <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Heuristic behavioral signals</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {report.suspiciousIndicators.map((ind, idx) => (
                <div
                  key={`ind-${idx}`}
                  className="rounded-xl border border-[var(--status-warning-border)] bg-[var(--surface-interactive)] p-3.5 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-xs text-[var(--status-warning)] flex items-center gap-1.5">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                      <span>{ind.name}</span>
                    </span>
                    <span className="rounded bg-[var(--status-warning-bg)] border border-[var(--status-warning-border)] px-1.5 py-0.5 text-[9px] font-mono font-semibold text-[var(--status-warning)] uppercase">
                      Behavioral Warning
                    </span>
                  </div>

                  <div className="rounded bg-[var(--background-secondary)] border border-[var(--border-subtle)] p-2 text-[11px] font-mono text-[var(--foreground-secondary)]">
                    <span className="text-[var(--muted-foreground)] mr-1.5">Evidence:</span>
                    <span className="text-[var(--foreground)]">&ldquo;{ind.evidence}&rdquo;</span>
                  </div>

                  <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                    {ind.reason}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SECTION 2: VERIFIED SOURCE CITATIONS & PROVENANCE */}
        {report.sources.length > 0 && (
          <div className="mt-7 space-y-3 border-t border-[var(--border-subtle)] pt-6">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
                <Globe className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span className="tabular-nums">Verified Research Citations ({report.sources.length})</span>
              </h4>
              <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Live internet references with provenance</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {report.sources.map((src) => {
                const provBadge = getProvenanceBadge(src.provenance);
                const isExpanded = expandedSourceId === src.id;

                return (
                  <div
                    key={src.id}
                    className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 flex flex-col justify-between hover:border-[var(--border)] transition-colors space-y-2"
                  >
                    <div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-[var(--muted-foreground)] mb-1 gap-2 flex-wrap">
                        <span className="text-[var(--accent-cyan)] font-semibold truncate max-w-[180px]">
                          {src.publisher || src.domain}
                        </span>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {src.relevanceGrade && (
                            <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono font-semibold ${getRelevanceBadge(src.relevanceGrade).color}`}>
                              {getRelevanceBadge(src.relevanceGrade).label}
                            </span>
                          )}
                          <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono font-semibold ${provBadge.color}`}>
                            {provBadge.label}
                          </span>
                        </div>
                      </div>

                      <a
                        href={src.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-bold text-[var(--foreground)] hover:text-[var(--primary-orange)] transition-colors line-clamp-2 inline-flex items-center gap-1 group break-all"
                      >
                        <span className="break-all">{src.title}</span>
                        <ExternalLink className="h-3 w-3 text-[var(--muted-foreground)] group-hover:text-[var(--primary-orange)] shrink-0" aria-hidden="true" />
                      </a>

                      <p className="mt-1.5 text-[11px] text-[var(--foreground-secondary)] line-clamp-3 leading-relaxed">
                        &ldquo;{src.snippet}&rdquo;
                      </p>

                      {src.rawContentExcerpt && (
                        <div className="mt-2 pt-2 border-t border-[var(--border-subtle)]">
                          <button
                            type="button"
                            aria-expanded={isExpanded}
                            onClick={() => setExpandedSourceId(isExpanded ? null : src.id)}
                            className="text-[10px] font-mono text-[var(--accent-cyan)] hover:underline inline-flex items-center gap-1 cursor-pointer font-semibold"
                          >
                            <FileText className="h-3 w-3" aria-hidden="true" />
                            <span>{isExpanded ? 'Hide Full Page Excerpt' : 'View Full Page Excerpt'}</span>
                            {isExpanded ? <ChevronUp className="h-2.5 w-2.5" aria-hidden="true" /> : <ChevronDown className="h-2.5 w-2.5" aria-hidden="true" />}
                          </button>

                          {isExpanded && (
                            <div className="mt-1.5 p-2.5 rounded bg-[var(--background-secondary)] border border-[var(--border-subtle)] text-[11px] font-mono text-[var(--foreground-secondary)] max-h-48 overflow-y-auto leading-relaxed break-all">
                              {src.rawContentExcerpt}
                            </div>
                          )}
                        </div>
                      )}

                      {src.relevanceExplanation && (
                        <p className="mt-1 text-[10px] text-[var(--muted-foreground)] font-mono italic">
                          Relevance: {src.relevanceExplanation}
                        </p>
                      )}

                      {src.limitationNote && (
                        <p className="mt-1 text-[10px] text-[var(--status-warning)] font-mono">
                          Limitation: {src.limitationNote}
                        </p>
                      )}
                    </div>

                    <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[10px] text-[var(--muted-foreground)] font-mono flex-wrap gap-1 tabular-nums">
                      <span>Retrieved: {new Date(src.retrievedAt).toLocaleDateString()}</span>
                      {src.publishedDate && <span>Published: {src.publishedDate}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* SECTION 3: SPECIALIZED THREAT INTELLIGENCE & DNS TELEMETRY */}
        {((report.domainIntelligence && report.domainIntelligence.length > 0) ||
          (report.threatIntel && report.threatIntel.length > 0)) && (
          <div className="mt-7 space-y-3 border-t border-[var(--border-subtle)] pt-6">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
                <Server className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>Specialized Threat Feeds &amp; DNS Infrastructure Telemetry</span>
              </h4>
              <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Authoritative lookups</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {report.threatIntel &&
                report.threatIntel.map((tRec, idx) => (
                  <div
                    key={`threat-${idx}`}
                    className={`rounded-xl border p-3.5 text-xs space-y-2 ${
                      tRec.status === 'malicious'
                        ? 'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)]'
                        : 'border-[var(--border-subtle)] bg-[var(--surface-interactive)]'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <span className="font-mono font-bold text-[var(--foreground)] text-xs break-all min-w-0">
                        {tRec.indicator}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border self-start sm:self-auto shrink-0 ${
                          tRec.status === 'malicious'
                            ? 'text-[var(--status-critical)] bg-[var(--surface)] border-[var(--status-critical-border)]'
                            : 'text-[var(--foreground-secondary)] bg-[var(--surface)] border-[var(--border)]'
                        }`}
                      >
                        {tRec.provider} &middot; {tRec.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">{tRec.details}</p>
                    <p className="text-[10px] text-[var(--status-warning)] font-mono">{tRec.importantNotice}</p>
                  </div>
                ))}

              {report.domainIntelligence &&
                report.domainIntelligence.map((dns) => (
                  <div
                    key={dns.domain}
                    className={`rounded-xl border p-3.5 text-xs space-y-2 ${
                      dns.isSuspiciousOrParked
                        ? 'border-[var(--status-warning-border)] bg-[var(--status-warning-bg)]'
                        : 'border-[var(--status-success-border)] bg-[var(--status-success-bg)]'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <span className="font-mono font-bold text-[var(--foreground)] text-xs break-all min-w-0">
                        {dns.domain}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border self-start sm:self-auto shrink-0 ${
                          dns.isSuspiciousOrParked
                            ? 'text-[var(--status-warning)] bg-[var(--surface)] border-[var(--status-warning-border)]'
                            : 'text-[var(--status-success)] bg-[var(--surface)] border-[var(--status-success-border)]'
                        }`}
                      >
                        {dns.isSuspiciousOrParked ? 'Anomalous Infrastructure' : 'Resolving Host'}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--foreground)] font-mono break-words">{dns.notes}</p>
                    <p className="text-[10px] text-[var(--foreground-secondary)] font-mono italic">{dns.caveat}</p>
                    <div className="flex items-center gap-3 text-[10px] font-mono text-[var(--muted-foreground)] flex-wrap tabular-nums">
                      <span>IPs: {dns.ipAddresses.length}</span>
                      <span>MX Mail Servers: {dns.mxRecordsCount}</span>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* SECTION 4: TAILORED DEFENSIVE ACTION RECOMMENDATIONS */}
        <div className="mt-7 border-t border-[var(--border-subtle)] pt-6 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
              <Shield className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
              <span>Recommended Next Steps &amp; Defensive Action Plan</span>
            </h4>

            {/* Audience Tabs */}
            <div
              role="tablist"
              aria-label="Recommendation audience"
              className="flex flex-wrap items-center gap-1 rounded-lg bg-[var(--surface-interactive)] p-1 border border-[var(--border-subtle)]"
            >
              <button
                type="button"
                role="tab"
                aria-selected={activeAudienceTab === 'individual'}
                onClick={() => setActiveAudienceTab('individual')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                  activeAudienceTab === 'individual'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                <UserCheck className="h-3 w-3" aria-hidden="true" />
                <span>Individuals</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeAudienceTab === 'org'}
                onClick={() => setActiveAudienceTab('org')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                  activeAudienceTab === 'org'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                <Building className="h-3 w-3" aria-hidden="true" />
                <span>Organizations</span>
              </button>
              {report.recommendations.forFinanceTeams && report.recommendations.forFinanceTeams.length > 0 && (
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeAudienceTab === 'finance'}
                  onClick={() => setActiveAudienceTab('finance')}
                  className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                    activeAudienceTab === 'finance'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                      : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  <Landmark className="h-3 w-3" aria-hidden="true" />
                  <span>Finance Teams</span>
                </button>
              )}
              <button
                type="button"
                role="tab"
                aria-selected={activeAudienceTab === 'security'}
                onClick={() => setActiveAudienceTab('security')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                  activeAudienceTab === 'security'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                <span>Security Teams</span>
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 text-xs">
            <ul className="space-y-2 text-[var(--foreground)]">
              {(activeAudienceTab === 'individual'
                ? report.recommendations.forIndividuals
                : activeAudienceTab === 'org'
                ? report.recommendations.forOrganizations
                : activeAudienceTab === 'finance'
                ? report.recommendations.forFinanceTeams || report.recommendations.forOrganizations
                : report.recommendations.forSecurityTeams
              ).map((act, i) => (
                <li key={i} className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[var(--status-success)] shrink-0 mt-0.5" aria-hidden="true" />
                  <span>{act}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* SECTION 5: UNRESOLVED QUESTIONS & RESEARCH LIMITATIONS */}
        <div className="mt-7 border-t border-[var(--border-subtle)] pt-5 space-y-3">
          {report.unresolvedQuestions && report.unresolvedQuestions.length > 0 && (
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1.5">
              <span className="text-[11px] font-semibold text-[var(--foreground)] flex items-center gap-1.5">
                <HelpCircle className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>Unresolved Questions for Independent Verification:</span>
              </span>
              <ul className="space-y-1 text-[11px] text-[var(--foreground-secondary)] list-disc list-inside">
                {report.unresolvedQuestions.map((q, qIdx) => (
                  <li key={qIdx}>{q}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3.5 text-[11px] text-[var(--foreground)] leading-relaxed">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-[var(--status-warning)] shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <strong className="text-[var(--status-warning)]">Fact-Checking Scope &amp; Legal Disclosures:</strong>{' '}
                {report.researchLimitations.join(' ')}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
