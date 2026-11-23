'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  AlertCircle,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  CheckSquare,
  Square,
  Cpu,
  FileText,
  RotateCcw,
  Link2,
  ArrowRight,
  FileCheck,
  Globe,
} from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';
import {
  DocumentScanResult,
  getDocumentAnalysisEngineDisplay,
} from '@/lib/document-scanner';

interface DocumentScanResultProps {
  result: DocumentScanResult;
  onReset: () => void;
}

export default function DocumentScanResultComponent({
  result,
  onReset,
}: DocumentScanResultProps) {
  const [completedActions, setCompletedActions] = useState<Record<number, boolean>>({});
  const [copiedReport, setCopiedReport] = useState(false);
  const [copiedIOCs, setCopiedIOCs] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const engineDisplay = getDocumentAnalysisEngineDisplay(result.analysisMode);

  const toggleAction = (idx: number) => {
    setCompletedActions((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const handleCopyReport = async () => {
    const reportText = `[AegisFlow Document Threat Analysis Report]
File: ${result.documentContent.filename} (${result.documentContent.mimeType})
Assessed Risk: ${result.riskLevel.toUpperCase()} (Score: ${result.severityScore ?? 'N/A'}/100)
Detected Type: ${result.documentContent.detectedType}
Stated Sender/Org: ${result.documentContent.apparentSenderOrOrganization || 'Unspecified'}

Summary:
${result.summary}

Extracted Content Snippet:
${result.documentContent.extractedTextSnippet}

Suspicious Elements:
${result.suspiciousElements.map((s) => `- [${s.category.toUpperCase()}] ${s.explanation} (Evidence: "${s.evidence}")`).join('\n')}

Unverified Claims:
${result.verificationStatus.unverifiedClaims.map((u) => `- ${u}`).join('\n')}

Recommended Next Steps:
${result.recommendedActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}

IOCs:
- URLs: ${result.iocs?.urls?.join(', ') || 'None'}
- Emails: ${result.iocs?.emails?.join(', ') || 'None'}
- Phone Numbers: ${result.iocs?.phoneNumbers?.join(', ') || 'None'}

Assessed by AegisFlow (Intelligence Engine: Aegis AI) at ${result.analyzedAt}`;

    await navigator.clipboard.writeText(reportText);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleCopyIOCs = async () => {
    const iocList = [
      ...(result.iocs?.urls || []).map((u) => `[URL] ${u}`),
      ...(result.iocs?.emails || []).map((e) => `[EMAIL] ${e}`),
      ...(result.iocs?.phoneNumbers || []).map((p) => `[PHONE] ${p}`),
      ...(result.iocs?.keywords || []).map((k) => `[TRIGGER-KEYWORD] ${k}`),
    ].join('\n');

    await navigator.clipboard.writeText(iocList || 'No IOCs detected.');
    setCopiedIOCs(true);
    setTimeout(() => setCopiedIOCs(false), 2000);
  };

  const totalIocsCount =
    (result.iocs?.urls?.length || 0) +
    (result.iocs?.emails?.length || 0) +
    (result.iocs?.phoneNumbers?.length || 0);

  return (
    <div className="space-y-6">
      {/* Top Banner & Assessment Card */}
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-7 shadow-[var(--shadow-sm)]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 border-b border-[var(--border-subtle)] pb-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <ThreatBadge
                level={result.riskLevel}
                score={result.severityScore}
                showScore={true}
                size="md"
              />
              {result.assessmentStateLabel && (
                <span className="rounded-lg bg-[var(--surface-interactive)] border border-[var(--border-subtle)] px-2.5 py-1 text-[11px] font-mono text-[var(--foreground)]">
                  {result.assessmentStateLabel}
                </span>
              )}
              {result.threatAssessment?.primaryCategoryLabel && (
                <span className="rounded-lg bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2.5 py-1 text-[11px] font-mono text-[var(--accent-cyan)]">
                  {result.threatAssessment.primaryCategoryLabel}
                </span>
              )}
              <span className="rounded-lg bg-[var(--surface-interactive)] border border-[var(--border-subtle)] px-2.5 py-1 text-[11px] font-mono text-[var(--foreground-secondary)] capitalize">
                Certainty:{' '}
                <strong className="text-[var(--foreground)]">
                  {result.evidenceCoverage === 'insufficient' || result.assessmentState === 'insufficient_information'
                    ? 'Indeterminate (Insufficient Evidence)'
                    : result.confidence}
                </strong>
              </span>
              <span
                className={`rounded-lg border px-2.5 py-1 text-[11px] font-mono font-medium ${
                  engineDisplay.isFallback
                    ? 'border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] text-[var(--status-warning)]'
                    : 'border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]'
                }`}
              >
                {engineDisplay.badge}
              </span>
            </div>
            <p className="text-[10px] font-mono text-[var(--muted-foreground)]">
              Normalized internal risk indicator (0–100), not a statistical probability of fraud.
            </p>
            <h3 className="text-xl sm:text-2xl font-extrabold text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Document Threat Analysis Report
            </h3>
            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed max-w-3xl">
              {result.summary}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-start lg:self-center shrink-0">
            <button
              type="button"
              onClick={handleCopyReport}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
            >
              {copiedReport ? (
                <Check className="h-3.5 w-3.5 text-[var(--status-success)]" aria-hidden="true" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
              )}
              <span>{copiedReport ? 'Copied' : 'Copy Report'}</span>
            </button>
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 hover:bg-[var(--primary-orange)]/15 px-3.5 py-2 text-xs font-semibold text-[var(--primary-orange)] transition-colors cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Scan Another Document</span>
            </button>
          </div>
        </div>

        {/* Dedicated BEC / Invoice Payment-Redirection / Verification Advisory */}
        {result.paymentChangeDetection?.detected && (
          <div
            className={`mt-5 rounded-xl border p-4 space-y-1.5 ${
              result.paymentChangeDetection.isActiveRedirectionRequest
                ? 'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)]'
                : 'border-[var(--status-warning-border)] bg-[var(--status-warning-bg)]'
            }`}
          >
            <div
              className={`flex items-center gap-2 text-xs font-bold ${
                result.paymentChangeDetection.isActiveRedirectionRequest
                  ? 'text-[var(--status-critical)]'
                  : 'text-[var(--status-warning)]'
              }`}
            >
              <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>
                {result.paymentChangeDetection.isActiveRedirectionRequest
                  ? 'Document Payment-Redirection / Business Email Compromise (BEC) Risk'
                  : result.paymentChangeDetection.isVerificationRequest
                  ? 'Bank-Account Change Verification Request (Confirm via Established Records)'
                  : 'Unverified Bank-Account Change Reference in Document'}
              </span>
            </div>
            <p className="text-xs text-[var(--foreground)] leading-relaxed">
              {result.paymentChangeDetection.rationale}
            </p>
          </div>
        )}

        {/* Separated 3-Dimension Security & Verification Assessment */}
        {result.threatAssessment && result.factualVerification && result.authenticityAssessment && (
          <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--primary-orange)]">
                Threat Assessment
              </span>
              <p className="text-xs font-bold text-[var(--foreground)]">
                {result.threatAssessment.primaryCategoryLabel}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {result.threatAssessment.summary}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--accent-cyan)]">
                Factual Verification
              </span>
              <p className="text-xs font-bold text-[var(--foreground)] capitalize">
                {result.factualVerification.status.replace(/_/g, ' ')}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {result.factualVerification.claimsSummary}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--accent-violet)]">
                Authenticity Assessment
              </span>
              <p className="text-xs font-bold text-[var(--foreground)] capitalize">
                {result.authenticityAssessment.status.replace(/_/g, ' ')}
              </p>
              <p className="text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                {result.authenticityAssessment.summary}
              </p>
            </div>
          </div>
        )}

        {/* SECTION 1: WHAT THE DOCUMENT ACTUALLY CONTAINS */}
        <div className="mt-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
              <FileText className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
              <span>1. What The Document Actually Contains</span>
            </h4>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)] break-all max-w-full">
              {result.documentContent.filename}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5">
              <span className="text-[10px] uppercase font-bold text-[var(--muted-foreground)]">Detected Category</span>
              <p className="mt-1 text-xs font-semibold text-[var(--foreground)] capitalize">
                {result.documentContent.detectedType.replace('_', ' ')}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 min-w-0">
              <span className="text-[10px] uppercase font-bold text-[var(--muted-foreground)]">Stated Sender / Organization</span>
              <p className="mt-1 text-xs font-semibold text-[var(--accent-cyan)] truncate">
                {result.documentContent.apparentSenderOrOrganization || 'Not explicitly stated'}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5 min-w-0">
              <span className="text-[10px] uppercase font-bold text-[var(--muted-foreground)]">Claimed Purpose</span>
              <p className="mt-1 text-xs font-semibold text-[var(--foreground)] truncate">
                {result.documentContent.claimedPurpose || 'Information request'}
              </p>
            </div>
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3.5">
              <span className="text-[10px] uppercase font-bold text-[var(--muted-foreground)]">File Type &amp; Size</span>
              <p className="mt-1 text-xs font-mono text-[var(--foreground-secondary)] break-words tabular-nums">
                {result.documentContent.mimeType} ({(result.documentContent.fileSizeBytes / 1024).toFixed(1)} KB)
                {result.documentContent.pageCount ? ` · ${result.documentContent.pageCount}p` : ''}
              </p>
            </div>
          </div>

          {/* Extracted Text Snippet */}
          {result.documentContent.extractedTextSnippet && (
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-2">
              <div className="flex items-center justify-between text-[11px] text-[var(--foreground-secondary)]">
                <span className="font-semibold text-[var(--foreground)]">Extracted Text Content (Untrusted Evidence):</span>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(result.documentContent.extractedTextSnippet);
                    setCopiedSnippet(true);
                    setTimeout(() => setCopiedSnippet(false), 2000);
                  }}
                  className="text-[var(--accent-cyan)] hover:underline inline-flex items-center gap-1 cursor-pointer font-medium"
                >
                  {copiedSnippet ? <Check className="h-3 w-3" aria-hidden="true" /> : <Copy className="h-3 w-3" aria-hidden="true" />}
                  <span>{copiedSnippet ? 'Copied' : 'Copy Text'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-[var(--foreground)] whitespace-pre-wrap break-words max-h-36 overflow-y-auto bg-[var(--background-secondary)] p-3 rounded-lg border border-[var(--border-subtle)]">
                {result.documentContent.extractedTextSnippet}
              </pre>
            </div>
          )}
        </div>

        {/* SECTION 2: WHAT APPEARS SUSPICIOUS */}
        <div className="mt-8 space-y-4 border-t border-[var(--border-subtle)] pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[var(--status-warning)]" aria-hidden="true" />
              <span>2. What Appears Suspicious (Threat Indicators)</span>
            </h4>
            <span className="text-[11px] font-mono font-semibold text-[var(--status-warning)] tabular-nums">
              {result.indicators.length + (result.suspiciousElements?.length || 0)} Anomalies Detected
            </span>
          </div>

          {result.suspiciousElements && result.suspiciousElements.length > 0 ? (
            <div className="space-y-2.5">
              {result.suspiciousElements.map((el, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3.5 space-y-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-[var(--surface)] border border-[var(--status-warning-border)] px-2 py-0.5 text-[10px] font-mono font-bold text-[var(--status-warning)] uppercase">
                      {el.category.replace('_', ' ')}
                    </span>
                    <p className="text-xs font-semibold text-[var(--foreground)]">{el.explanation}</p>
                  </div>
                  {el.evidence && (
                    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--background-secondary)] px-3 py-2 text-xs font-mono text-[var(--foreground-secondary)] break-words">
                      &ldquo;{el.evidence}&rdquo;
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : result.indicators.length > 0 ? (
            <div className="space-y-2.5">
              {result.indicators.map((ind, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3.5 space-y-1.5"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-[var(--foreground)]">{ind.name}</span>
                  </div>
                  <p className="text-xs text-[var(--foreground-secondary)]">{ind.reason}</p>
                  {ind.evidence && (
                    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--background-secondary)] px-3 py-2 text-xs font-mono text-[var(--foreground-secondary)] break-words">
                      &ldquo;{ind.evidence}&rdquo;
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 text-xs text-[var(--foreground-secondary)] text-center">
              No obvious coercive manipulation or phishing indicators identified in visible text.
            </div>
          )}
        </div>

        {/* SECTION 3: WHAT HAS OR HAS NOT BEEN INDEPENDENTLY VERIFIED */}
        <div className="mt-8 space-y-4 border-t border-[var(--border-subtle)] pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
              <FileCheck className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
              <span>3. Independent Verification Status</span>
            </h4>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">Zero Unverified Trust</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Unverified Claims */}
            <div className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-[var(--status-critical)]">
                <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>Unverified Claims (Do Not Assume Legitimate)</span>
              </div>
              <ul className="space-y-1.5 text-xs text-[var(--foreground)] list-disc list-inside">
                {result.verificationStatus.unverifiedClaims.map((claim, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {claim}
                  </li>
                ))}
              </ul>
            </div>

            {/* Verified Elements */}
            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-[var(--accent-cyan)]">
                <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>Independently Verified Elements</span>
              </div>
              {result.verificationStatus.independentlyVerified.length > 0 ? (
                <ul className="space-y-1.5 text-xs text-[var(--foreground)] list-disc list-inside">
                  {result.verificationStatus.independentlyVerified.map((v, idx) => (
                    <li key={idx}>{v}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                  No claims or senders are verified. Automated AI inspection cannot confirm company authorization, banking ownership, or external DNS certificates.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* SECTION 4: WHAT THE USER SHOULD DO NEXT */}
        <div className="mt-8 space-y-4 border-t border-[var(--border-subtle)] pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-[var(--status-success)]" aria-hidden="true" />
              <span>4. Recommended Next Steps (Action Checklist)</span>
            </h4>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)] tabular-nums">
              {Object.values(completedActions).filter(Boolean).length} of {result.recommendedActions.length} completed
            </span>
          </div>

          <div className="space-y-2">
            {result.recommendedActions.map((action, idx) => {
              const isDone = Boolean(completedActions[idx]);
              return (
                <button
                  key={idx}
                  type="button"
                  aria-pressed={isDone}
                  onClick={() => toggleAction(idx)}
                  className={`w-full flex items-start gap-3 rounded-xl border p-3.5 text-left transition-colors cursor-pointer ${
                    isDone
                      ? 'border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[var(--muted-foreground)] line-through'
                      : 'border-[var(--border-subtle)] bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40 text-[var(--foreground)]'
                  }`}
                >
                  {isDone ? (
                    <CheckSquare className="h-4 w-4 text-[var(--status-success)] mt-0.5 shrink-0" aria-hidden="true" />
                  ) : (
                    <Square className="h-4 w-4 text-[var(--muted-foreground)] mt-0.5 shrink-0" aria-hidden="true" />
                  )}
                  <span className="text-xs font-medium leading-relaxed">{action}</span>
                </button>
              );
            })}
          </div>

          {result.financeRecommendations &&
            result.financeRecommendations.length > 0 &&
            (result.paymentChangeDetection?.detected ||
              result.primaryThreatCategory === 'executive_impersonation' ||
              result.primaryThreatCategory === 'payroll_diversion') && (
              <div className="mt-4 rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-4 space-y-2">
                <span className="text-xs font-bold text-[var(--status-warning)] flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>Finance &amp; Accounts Payable Verification Controls</span>
                </span>
                <ul className="space-y-1 text-xs text-[var(--foreground)] list-disc list-inside">
                  {result.financeRecommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
        </div>

        {/* SECTION 5: EXTRACTED INDICATORS OF COMPROMISE (IOCs) */}
        {totalIocsCount > 0 && (
          <div className="mt-8 space-y-4 border-t border-[var(--border-subtle)] pt-6">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
                <Link2 className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
                <span>Extracted Indicators of Compromise (IOC Vault)</span>
              </h4>
              <button
                type="button"
                onClick={handleCopyIOCs}
                className="text-[11px] font-medium text-[var(--accent-cyan)] hover:underline inline-flex items-center gap-1 cursor-pointer"
              >
                {copiedIOCs ? <Check className="h-3 w-3" aria-hidden="true" /> : <Copy className="h-3 w-3" aria-hidden="true" />}
                <span>{copiedIOCs ? 'Copied' : 'Copy All IOCs'}</span>
              </button>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 space-y-3">
              <p className="text-[11px] text-[var(--status-warning)] flex items-center gap-1.5">
                <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>Security Notice: URLs and email addresses extracted from untrusted materials are never automatically visited.</span>
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                {result.iocs?.urls && result.iocs.urls.length > 0 && (
                  <div className="space-y-1 min-w-0">
                    <span className="text-[10px] font-bold uppercase text-[var(--muted-foreground)]">Extracted URLs</span>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.iocs.urls.map((u, i) => (
                        <div key={i} className="text-xs font-mono text-[var(--accent-cyan)] break-all bg-[var(--background-secondary)] p-1.5 rounded border border-[var(--border-subtle)]">
                          {u}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.iocs?.emails && result.iocs.emails.length > 0 && (
                  <div className="space-y-1 min-w-0">
                    <span className="text-[10px] font-bold uppercase text-[var(--muted-foreground)]">Extracted Emails</span>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.iocs.emails.map((e, i) => (
                        <div key={i} className="text-xs font-mono text-[var(--accent-violet)] break-all bg-[var(--background-secondary)] p-1.5 rounded border border-[var(--border-subtle)]">
                          {e}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.iocs?.phoneNumbers && result.iocs.phoneNumbers.length > 0 && (
                  <div className="space-y-1 min-w-0">
                    <span className="text-[10px] font-bold uppercase text-[var(--muted-foreground)]">Extracted Phone Numbers</span>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.iocs.phoneNumbers.map((p, i) => (
                        <div key={i} className="text-xs font-mono text-[var(--status-success)] break-all bg-[var(--background-secondary)] p-1.5 rounded border border-[var(--border-subtle)]">
                          {p}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Footer Navigation & Vault Reference */}
        <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-subtle)] pt-5 text-xs text-[var(--foreground-secondary)]">
          <div className="flex flex-wrap items-center gap-2">
            <Cpu className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
            <span>
              Intelligence: <strong className="text-[var(--foreground)]">{engineDisplay.label}</strong>
            </span>
            {result.statusNotice && (
              <span className="text-[11px] text-[var(--muted-foreground)]">
                &middot; {result.statusNotice}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/analyze?tab=factcheck"
              onClick={() => {
                if (typeof window !== 'undefined' && result.documentContent.extractedTextSnippet) {
                  sessionStorage.setItem('aegisflow_factcheck_preload', result.documentContent.extractedTextSnippet);
                }
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] hover:opacity-90 px-3 py-1.5 text-xs font-semibold text-[var(--accent-cyan)] transition-opacity"
            >
              <Globe className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Fact-Check Claims</span>
            </Link>

            <Link
              href="/investigations"
              className="text-[var(--primary-orange)] hover:underline font-semibold inline-flex items-center gap-1"
            >
              <span>View in Investigation Vault</span>
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
