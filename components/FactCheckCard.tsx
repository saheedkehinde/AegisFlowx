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
  Copy,
  Check,
  Clock,
  Info,
  FileText,
  Search,
  MessageSquare,
  AlertOctagon,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { FactCheckReport, FactualClaim, ResearchSource, SourceProvenance } from '@/lib/fact-checker/types';

interface FactCheckCardProps {
  report: FactCheckReport;
  onReset?: () => void;
}

export default function FactCheckCard({ report, onReset }: FactCheckCardProps) {
  const [activeAudienceTab, setActiveAudienceTab] = useState<'individual' | 'org' | 'security'>('individual');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedSourceId, setExpandedSourceId] = useState<string | null>(null);

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getVerdictBadge = (verdict: FactualClaim['verdict']) => {
    switch (verdict) {
      case 'supported':
        return {
          label: 'Supported by Available Evidence',
          color: 'text-emerald-400 bg-emerald-950/50 border-emerald-500/30',
          icon: CheckCircle2,
        };
      case 'contradicted':
        return {
          label: 'Contradicted by Available Evidence',
          color: 'text-red-400 bg-red-950/50 border-red-500/30',
          icon: XCircle,
        };
      case 'misleading':
        return {
          label: 'Misleading / Missing Context',
          color: 'text-amber-400 bg-amber-950/50 border-amber-500/30',
          icon: AlertTriangle,
        };
      case 'unverified_suspicious':
        return {
          label: 'Suspicious / Not Independently Verified',
          color: 'text-purple-400 bg-purple-950/50 border-purple-500/30',
          icon: ShieldAlert,
        };
      case 'no_verifiable_claim':
        return {
          label: 'No Independently Verifiable Claim Identified',
          color: 'text-indigo-400 bg-indigo-950/50 border-indigo-500/30',
          icon: MessageSquare,
        };
      case 'inconclusive':
      default:
        return {
          label: 'Inconclusive (Evidence Insufficient)',
          color: 'text-slate-400 bg-slate-900 border-white/10',
          icon: HelpCircle,
        };
    }
  };

  const getProvenanceBadge = (provenance: SourceProvenance) => {
    switch (provenance) {
      case 'full_page_retrieved':
        return {
          label: 'Full Webpage Retrieved',
          color: 'text-cyan-400 bg-cyan-950/50 border-cyan-500/30',
        };
      case 'encyclopedia':
        return {
          label: 'Official Encyclopedia',
          color: 'text-blue-400 bg-blue-950/50 border-blue-500/30',
        };
      case 'authoritative_dns':
        return {
          label: 'Authoritative DNS Telemetry',
          color: 'text-purple-400 bg-purple-950/50 border-purple-500/30',
        };
      case 'threat_intelligence':
        return {
          label: 'Threat Feed Match',
          color: 'text-red-400 bg-red-950/50 border-red-500/30',
        };
      case 'page_retrieval_failed':
        return {
          label: 'Page Retrieval Failed (Snippet Only)',
          color: 'text-amber-400 bg-amber-950/50 border-amber-500/30',
        };
      case 'snippet_only':
      default:
        return {
          label: 'Search Snippet Only',
          color: 'text-slate-400 bg-slate-900 border-white/10',
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Fact-Checking Dossier Banner */}
      <div className="rounded-2xl border border-cyan-500/30 bg-[#0d1322] p-5 sm:p-7 shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-950/60 px-2.5 py-0.5 text-[10px] font-mono text-cyan-300 font-semibold">
                <Globe className="h-3 w-3 animate-pulse text-cyan-400" />
                <span>Evidence-Based Web Research Dossier</span>
              </span>
              <span className="text-xs font-mono text-slate-500">
                {new Date(report.analyzedAt).toLocaleTimeString()}
              </span>

              {/* Search Provider Badge */}
              <span className="rounded-md bg-slate-900 border border-white/10 px-2 py-0.5 text-[10px] font-mono text-slate-300">
                Provider: <strong className="text-cyan-300">{report.searchProviderStatus?.providerName || report.searchProviderUsed}</strong>
              </span>

              {report.searchProviderStatus?.fullPageRetrievalActive && (
                <span className="rounded-md bg-emerald-950/50 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono text-emerald-300">
                  📄 Full-Page Content Retrieved
                </span>
              )}
            </div>

            <h3 className="mt-1 text-xl sm:text-2xl font-extrabold text-white">
              Evidence-Based Intelligence Report
            </h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed max-w-3xl">
              {report.executiveSummary}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-start lg:self-center shrink-0">
            <span className="rounded-lg bg-slate-900 border border-white/10 px-3 py-1.5 text-xs font-mono text-cyan-300">
              Confidence: <strong className="capitalize text-white">{report.confidenceLevel}</strong>
            </span>
            {onReset && (
              <button
                type="button"
                onClick={onReset}
                className="rounded-xl border border-white/10 bg-slate-900 hover:bg-slate-800 px-3.5 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                New Fact-Check
              </button>
            )}
          </div>
        </div>

        {/* Rate limit warning if encountered */}
        {report.searchProviderStatus?.rateLimitEncountered && (
          <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>Search API rate limit reached. Analysis automatically utilized Wikimedia public registries and cached index fallbacks.</span>
          </div>
        )}

        {/* Non-Verifiable Communication Banner (Conversational Greetings) */}
        {!report.hasVerifiableClaims && (
          <div className="mt-5 rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-4 space-y-2">
            <div className="flex items-center gap-2 text-indigo-300 font-semibold text-xs">
              <MessageSquare className="h-4 w-4 text-indigo-400" />
              <span>Conversational / Non-Factual Inquiry Detected</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This message contains polite greetings, personal check-ins, or general inquiries without verifiable corporate claims, invoices, or transactional instructions. No external searches were executed because there are no factual claims to verify.
            </p>
            <p className="text-[11px] text-slate-400">
              Security note: Unsolicited friendly greetings from unknown senders are frequently used as initial engagement probes in multi-stage social engineering (such as romance or task scams).
            </p>
          </div>
        )}

        {/* SECTION 1: CLAIMS IDENTIFIED & CROSS-EXAMINATION */}
        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              <span>Extracted Claims &amp; Evidence Cross-Examination ({report.extractedClaims.length})</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">Qualified evidence assessment</span>
          </div>

          <div className="space-y-3">
            {report.extractedClaims.map((claim) => {
              const badge = getVerdictBadge(claim.verdict);
              const VerdictIcon = badge.icon;

              return (
                <div
                  key={claim.id}
                  className="rounded-xl border border-white/5 bg-[#090d18] p-4 space-y-3 hover:border-cyan-500/20 transition-colors"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-xs font-medium text-white break-words flex-1">
                      &ldquo;{claim.claimText}&rdquo;
                    </span>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[10px] font-mono font-semibold shrink-0 ${badge.color}`}
                    >
                      <VerdictIcon className="h-3 w-3" />
                      <span>{badge.label}</span>
                    </span>
                  </div>

                  {claim.evidenceNeeded && (
                    <div className="text-[11px] text-slate-400 font-mono flex items-start gap-1.5 bg-black/30 p-2 rounded border border-white/5">
                      <span className="text-cyan-400 font-semibold shrink-0">Verification Criteria:</span>
                      <span>{claim.evidenceNeeded}</span>
                    </div>
                  )}

                  <p className="text-xs text-slate-300 italic border-l-2 border-cyan-500/40 pl-2.5">
                    {claim.verdictExplanation}
                  </p>

                  {/* Contradicting Evidence */}
                  {claim.contradictingEvidence.length > 0 && (
                    <div className="rounded-lg bg-red-950/20 border border-red-500/20 p-2.5 text-xs space-y-1">
                      <span className="font-semibold text-red-300 flex items-center gap-1 text-[11px]">
                        <XCircle className="h-3.5 w-3.5 text-red-400" />
                        <span>Contradicting Evidence &amp; Public Advisories:</span>
                      </span>
                      <ul className="space-y-1 text-slate-300 text-[11px]">
                        {claim.contradictingEvidence.map((ev, i) => (
                          <li key={i} className="pl-2 border-l border-red-500/30">
                            {ev}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Supporting Evidence */}
                  {claim.supportingEvidence.length > 0 && (
                    <div className="rounded-lg bg-emerald-950/20 border border-emerald-500/20 p-2.5 text-xs space-y-1">
                      <span className="font-semibold text-emerald-300 flex items-center gap-1 text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>Supporting Corroboration:</span>
                      </span>
                      <ul className="space-y-1 text-slate-300 text-[11px]">
                        {claim.supportingEvidence.map((ev, i) => (
                          <li key={i} className="pl-2 border-l border-emerald-500/30">
                            {ev}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Cited Source URLs for this claim */}
                  {claim.citedSourceUrls.length > 0 && (
                    <div className="pt-1 flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                      <span className="text-slate-500">Direct Sources:</span>
                      {claim.citedSourceUrls.map((cUrl, idx) => (
                        <a
                          key={idx}
                          href={cUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline bg-slate-900 px-1.5 py-0.5 rounded border border-white/5 truncate max-w-[200px]"
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

        {/* SECTION 2: VERIFIED SOURCE CITATIONS & PROVENANCE */}
        {report.sources.length > 0 && (
          <div className="mt-7 space-y-3 border-t border-white/5 pt-6">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan-400" />
                <span>Verified Research Citations ({report.sources.length})</span>
              </h4>
              <span className="text-[11px] font-mono text-slate-500">Live internet references with provenance</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {report.sources.map((src) => {
                const provBadge = getProvenanceBadge(src.provenance);
                const isExpanded = expandedSourceId === src.id;

                return (
                  <div
                    key={src.id}
                    className="rounded-xl border border-white/5 bg-[#090d18] p-3.5 flex flex-col justify-between hover:border-cyan-500/40 transition-all space-y-2"
                  >
                    <div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                        <span className="text-cyan-400 font-semibold truncate max-w-[180px]">
                          {src.publisher || src.domain}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${provBadge.color}`}>
                          {provBadge.label}
                        </span>
                      </div>

                      <a
                        href={src.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-bold text-white hover:text-cyan-300 transition-colors line-clamp-1 inline-flex items-center gap-1 group"
                      >
                        <span>{src.title}</span>
                        <ExternalLink className="h-3 w-3 text-slate-500 group-hover:text-cyan-400 shrink-0" />
                      </a>

                      <p className="mt-1.5 text-[11px] text-slate-300 line-clamp-3 leading-relaxed">
                        &ldquo;{src.snippet}&rdquo;
                      </p>

                      {/* Expandable full-page raw content excerpt if retrieved */}
                      {src.rawContentExcerpt && (
                        <div className="mt-2 pt-2 border-t border-white/5">
                          <button
                            type="button"
                            onClick={() => setExpandedSourceId(isExpanded ? null : src.id)}
                            className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer"
                          >
                            <FileText className="h-3 w-3" />
                            <span>{isExpanded ? 'Hide Full Page Excerpt' : 'View Full Page Excerpt'}</span>
                            {isExpanded ? <ChevronUp className="h-2.5 w-2.5" /> : <ChevronDown className="h-2.5 w-2.5" />}
                          </button>

                          {isExpanded && (
                            <div className="mt-1.5 p-2.5 rounded bg-black/50 border border-white/10 text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto leading-relaxed">
                              {src.rawContentExcerpt}
                            </div>
                          )}
                        </div>
                      )}

                      {src.relevanceExplanation && (
                        <p className="mt-1 text-[10px] text-slate-400 font-mono italic">
                          Relevance: {src.relevanceExplanation}
                        </p>
                      )}
                    </div>

                    <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-500 font-mono">
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
          <div className="mt-7 space-y-3 border-t border-white/5 pt-6">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Server className="h-4 w-4 text-cyan-400" />
                <span>Specialized Threat Feeds &amp; DNS Infrastructure Telemetry</span>
              </h4>
              <span className="text-[11px] font-mono text-slate-500">Authoritative lookups</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Threat Feed Records (URLhaus / abuse.ch) */}
              {report.threatIntel &&
                report.threatIntel.map((tRec, idx) => (
                  <div
                    key={`threat-${idx}`}
                    className={`rounded-xl border p-3.5 text-xs space-y-2 ${
                      tRec.status === 'malicious'
                        ? 'border-red-500/40 bg-red-950/20'
                        : 'border-white/10 bg-[#090d18]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-white text-xs truncate max-w-[200px]">
                        {tRec.indicator}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          tRec.status === 'malicious'
                            ? 'text-red-400 bg-red-950/40 border-red-500/30'
                            : 'text-slate-400 bg-slate-900 border-white/10'
                        }`}
                      >
                        {tRec.provider} &middot; {tRec.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300">{tRec.details}</p>
                    <p className="text-[10px] text-amber-400/90 font-mono">{tRec.importantNotice}</p>
                  </div>
                ))}

              {/* DNS Telemetry Records */}
              {report.domainIntelligence &&
                report.domainIntelligence.map((dns) => (
                  <div
                    key={dns.domain}
                    className={`rounded-xl border p-3.5 text-xs space-y-2 ${
                      dns.isSuspiciousOrParked
                        ? 'border-amber-500/30 bg-amber-950/10'
                        : 'border-emerald-500/30 bg-emerald-950/10'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-white text-xs truncate max-w-[200px]">
                        {dns.domain}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          dns.isSuspiciousOrParked
                            ? 'text-amber-400 bg-amber-950/40 border-amber-500/30'
                            : 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30'
                        }`}
                      >
                        {dns.isSuspiciousOrParked ? 'Anomalous Infrastructure' : 'Resolving Host'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 font-mono">{dns.notes}</p>
                    <p className="text-[10px] text-slate-400 font-mono italic">{dns.caveat}</p>
                    <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400">
                      <span>IPs: {dns.ipAddresses.length}</span>
                      <span>MX Mail Servers: {dns.mxRecordsCount}</span>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* SECTION 4: TAILORED DEFENSIVE ACTION RECOMMENDATIONS */}
        <div className="mt-7 border-t border-white/5 pt-6 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              <span>Recommended Next Steps &amp; Defensive Action Plan</span>
            </h4>

            {/* Audience Tabs */}
            <div className="flex items-center gap-1 rounded-lg bg-slate-900 p-1 border border-white/5">
              <button
                type="button"
                onClick={() => setActiveAudienceTab('individual')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors cursor-pointer ${
                  activeAudienceTab === 'individual'
                    ? 'bg-cyan-600 text-white font-semibold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <UserCheck className="h-3 w-3" />
                <span>Individuals</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveAudienceTab('org')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors cursor-pointer ${
                  activeAudienceTab === 'org'
                    ? 'bg-cyan-600 text-white font-semibold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Building className="h-3 w-3" />
                <span>Organizations</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveAudienceTab('security')}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors cursor-pointer ${
                  activeAudienceTab === 'security'
                    ? 'bg-cyan-600 text-white font-semibold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <ShieldAlert className="h-3 w-3" />
                <span>Security Teams</span>
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 text-xs">
            <ul className="space-y-2 text-slate-300">
              {(activeAudienceTab === 'individual'
                ? report.recommendations.forIndividuals
                : activeAudienceTab === 'org'
                ? report.recommendations.forOrganizations
                : report.recommendations.forSecurityTeams
              ).map((act, i) => (
                <li key={i} className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{act}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* SECTION 5: UNRESOLVED QUESTIONS & RESEARCH LIMITATIONS */}
        <div className="mt-7 border-t border-white/5 pt-5 space-y-3">
          {report.unresolvedQuestions && report.unresolvedQuestions.length > 0 && (
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5 space-y-1.5">
              <span className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                <HelpCircle className="h-3.5 w-3.5 text-cyan-400" />
                <span>Unresolved Questions for Independent Verification:</span>
              </span>
              <ul className="space-y-1 text-[11px] text-slate-400 list-disc list-inside">
                {report.unresolvedQuestions.map((q, qIdx) => (
                  <li key={qIdx}>{q}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-3.5 text-[11px] text-amber-300/90 leading-relaxed">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong>Fact-Checking Scope &amp; Legal Disclosures:</strong>{' '}
                {report.researchLimitations.join(' ')}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
