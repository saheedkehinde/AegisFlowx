'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Clock,
  Info,
  CheckSquare,
  Square,
  Cpu,
  FileWarning,
  Terminal,
  RotateCcw,
  Sparkles,
  Link2,
  Mail,
  Phone,
  Key,
  HelpCircle,
  Gauge,
  Layers,
  ArrowRight,
  Globe,
} from 'lucide-react';
import Link from 'next/link';
import ThreatBadge from '@/components/ui/ThreatBadge';
import { ScamAnalysisResult, RiskLevel } from '@/lib/scam-analyzer';

interface AnalysisResultProps {
  result: ScamAnalysisResult;
  onReset: () => void;
}

export default function AnalysisResult({ result, onReset }: AnalysisResultProps) {
  const [completedActions, setCompletedActions] = useState<Record<number, boolean>>({});
  const [copied, setCopied] = useState(false);
  const [copiedIOCs, setCopiedIOCs] = useState(false);

  const toggleAction = (index: number) => {
    setCompletedActions((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const handleMarkAllActions = (complete: boolean) => {
    const updated: Record<number, boolean> = {};
    result.recommendedActions.forEach((_, idx) => {
      updated[idx] = complete;
    });
    setCompletedActions(updated);
  };

  const handleCopyReport = async () => {
    const reportText = `[AegisFlow Incident Advisory — Aegis AI Threat Analysis]
Risk Level: ${result.riskLevel.toUpperCase()}
Evidence Depth: ${result.evidenceSufficiency.toUpperCase()}
Model Confidence: ${result.confidence.toUpperCase()}
Intelligence Engine: Aegis AI
Analyzed At: ${result.analyzedAt || 'N/A'}

EXECUTIVE SUMMARY:
${result.summary}

CONFIDENCE RATIONALE:
${result.confidenceRationale}

EVIDENCE & WARNING SIGNS (${result.indicators.length}):
${
  result.indicators.length > 0
    ? result.indicators
        .map(
          (item, idx) =>
            `${idx + 1}. [${item.name}]
   Evidence: "${item.evidence}"
   Reason: ${item.reason}`
        )
        .join('\n\n')
    : 'No adversarial threat indicators were identified in this message.'
}

RECOMMENDED SAFETY ACTIONS:
${result.recommendedActions.map((action, idx) => `${idx + 1}. ${action}`).join('\n')}

LIMITATIONS & UNCERTAINTIES:
${result.limitations.map((lim) => `- ${lim}`).join('\n')}
`;

    try {
      await navigator.clipboard.writeText(reportText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback if clipboard API is restricted
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const handleCopyDefangedIOCs = async () => {
    const defangedUrls = (result.iocs?.urls || []).map((u) => u.replace('http', 'hxxp').replace('.', '[.]'));
    const defangedEmails = (result.iocs?.emails || []).map((e) => e.replace('@', ' [at] '));
    const lines = [
      '# AegisFlow Extracted Defanged IOCs',
      `# Risk: ${result.riskLevel.toUpperCase()} | Engine: Aegis AI`,
      '# Generated: ' + (result.analyzedAt || new Date().toISOString()),
      '',
      '## URLs (Defanged):',
      ...(defangedUrls.length > 0 ? defangedUrls : ['None detected']),
      '',
      '## Emails (Defanged):',
      ...(defangedEmails.length > 0 ? defangedEmails : ['None detected']),
      '',
      '## Phone Numbers:',
      ...(result.iocs?.phoneNumbers && result.iocs.phoneNumbers.length > 0
        ? result.iocs.phoneNumbers
        : ['None detected']),
    ];

    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setCopiedIOCs(true);
      setTimeout(() => setCopiedIOCs(false), 2500);
    } catch {
      setCopiedIOCs(true);
      setTimeout(() => setCopiedIOCs(false), 2500);
    }
  };

  // Badge configurations based on Risk Level
  const getRiskBadgeConfig = (level: RiskLevel) => {
    switch (level) {
      case 'high':
        return {
          icon: AlertOctagon,
          label: 'HIGH RISK',
          subLabel: 'Critical scam, impersonation, or credential harvest vectors detected',
          borderClass: 'border-[var(--status-critical-border)]',
          bgClass: 'bg-[var(--card-bg)]',
          accentBg: 'bg-[var(--status-critical-bg)] text-[var(--status-critical)] border-[var(--status-critical-border)]',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          label: 'MEDIUM RISK',
          subLabel: 'Suspicious coercive or anomalous elements detected',
          borderClass: 'border-[var(--status-warning-border)]',
          bgClass: 'bg-[var(--card-bg)]',
          accentBg: 'bg-[var(--status-warning-bg)] text-[var(--status-warning)] border-[var(--status-warning-border)]',
        };
      case 'low':
        return {
          icon: ShieldCheck,
          label: 'LOW RISK',
          subLabel: 'No active fraud or social engineering markers detected',
          borderClass: 'border-[var(--status-success-border)]',
          bgClass: 'bg-[var(--card-bg)]',
          accentBg: 'bg-[var(--status-success-bg)] text-[var(--status-success)] border-[var(--status-success-border)]',
        };
      case 'uncertain':
      default:
        return {
          icon: ShieldQuestion,
          label: 'UNCERTAIN',
          subLabel: 'Inconclusive telemetry: context is insufficient to determine intent',
          borderClass: 'border-[var(--status-uncertain-border)]',
          bgClass: 'bg-[var(--card-bg)]',
          accentBg: 'bg-[var(--status-uncertain-bg)] text-[var(--status-uncertain)] border-[var(--status-uncertain-border)]',
        };
    }
  };

  const badgeConfig = getRiskBadgeConfig(result.riskLevel);
  const RiskIcon = badgeConfig.icon;

  const totalActions = result.recommendedActions.length;
  const completedCount = Object.values(completedActions).filter(Boolean).length;
  const progressPercent = totalActions > 0 ? Math.round((completedCount / totalActions) * 100) : 0;

  const hasIOCs =
    (result.iocs?.urls.length || 0) > 0 ||
    (result.iocs?.emails.length || 0) > 0 ||
    (result.iocs?.phoneNumbers.length || 0) > 0;

  return (
    <section
      id="results-section"
      tabIndex={-1}
      aria-label="Security Analysis Results"
      className="mx-auto max-w-5xl mt-10 outline-none"
    >
      <div
        className={`relative rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.bgClass} p-5 sm:p-8 shadow-[var(--shadow-lg)] transition-all`}
      >
        {/* Top Header: Risk Classification & Quick Controls */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-5 border-b border-[var(--border)] pb-6">
          <div className="flex items-start sm:items-center gap-4">
            {/* Risk Badge Icon Box */}
            <div
              className={`flex h-14 w-14 sm:h-16 sm:w-16 shrink-0 items-center justify-center rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.accentBg}`}
            >
              <RiskIcon className="h-7 w-7 sm:h-8 sm:w-8" />
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <ThreatBadge
                  level={result.riskLevel}
                  score={result.severityScore}
                  showScore={true}
                  size="lg"
                />
                {result.assessmentStateLabel && (
                  <span className="rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] font-mono font-semibold text-[var(--foreground)]">
                    {result.assessmentStateLabel}
                  </span>
                )}
                {result.threatAssessment?.primaryCategoryLabel && (
                  <span className="rounded-lg border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] px-2.5 py-1 text-[11px] font-mono text-[var(--accent-cyan)]">
                    {result.threatAssessment.primaryCategoryLabel}
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-xs sm:text-sm text-[var(--foreground-secondary)]">
                {badgeConfig.subLabel}
              </p>
              <p className="mt-0.5 text-[11px] font-mono text-[var(--muted-foreground)]">
                Normalized internal risk indicator (0–100), not a statistical probability of fraud.
              </p>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 pt-2 md:pt-0">
            <button
              onClick={handleCopyReport}
              type="button"
              className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-medium text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="h-4 w-4 text-[var(--status-success)]" />
                  <span className="text-[var(--status-success)] font-semibold">Advisory Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4 text-[var(--muted-foreground)]" />
                  <span>Copy Advisory</span>
                </>
              )}
            </button>

            {hasIOCs && (
              <button
                onClick={handleCopyDefangedIOCs}
                type="button"
                className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2 text-xs font-medium text-[var(--foreground)] hover:border-[var(--accent-cyan)]/40 transition-colors focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
              >
                {copiedIOCs ? (
                  <>
                    <Check className="h-4 w-4 text-[var(--accent-cyan)]" />
                    <span className="text-[var(--accent-cyan)] font-semibold">IOCs Copied</span>
                  </>
                ) : (
                  <>
                    <Terminal className="h-4 w-4 text-[var(--accent-cyan)]" />
                    <span>Copy Defanged IOCs</span>
                  </>
                )}
              </button>
            )}

            <Link
              href="/analyze?tab=factcheck"
              onClick={() => {
                if (typeof window !== 'undefined') {
                  const textarea = document.getElementById('message-input') as HTMLTextAreaElement | null;
                  const textToPreload = textarea?.value || result.summary;
                  sessionStorage.setItem('aegisflow_factcheck_preload', textToPreload);
                }
              }}
              className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-cyan)] hover:opacity-90 transition-opacity focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
            >
              <Globe className="h-4 w-4" />
              <span>Fact-Check Claims</span>
            </Link>

            <button
              onClick={onReset}
              type="button"
              className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] px-3.5 py-2 text-xs font-semibold text-[var(--primary-orange)] hover:opacity-90 transition-opacity focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
            >
              <RotateCcw className="h-4 w-4" />
              <span>Analyze Another</span>
            </button>
          </div>
        </div>

        {/* Essential Cyber Telemetry: Distinguishing Risk, Sufficiency & Model Certainty */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3 flex flex-col justify-between">
            <span className="text-[var(--muted-foreground)] text-[11px] font-mono uppercase tracking-wider">
              1. Threat Severity
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor:
                    result.riskLevel === 'high'
                      ? 'var(--status-critical)'
                      : result.riskLevel === 'medium'
                      ? 'var(--status-warning)'
                      : result.riskLevel === 'low'
                      ? 'var(--status-success)'
                      : 'var(--status-uncertain)',
                }}
              />
              <span className="font-bold text-[var(--foreground)] uppercase">{result.riskLevel} Risk</span>
            </div>
          </div>

          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3 flex flex-col justify-between">
            <span className="text-[var(--muted-foreground)] text-[11px] font-mono uppercase tracking-wider">
              2. Evidence Context Depth
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor:
                    result.evidenceSufficiency === 'sufficient'
                      ? 'var(--accent-cyan)'
                      : result.evidenceSufficiency === 'moderate'
                      ? 'var(--status-warning)'
                      : 'var(--muted-foreground)',
                }}
              />
              <span className="font-bold text-[var(--foreground)] capitalize">{result.evidenceSufficiency} Context</span>
            </div>
          </div>

          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3 flex flex-col justify-between">
            <span className="text-[var(--muted-foreground)] text-[11px] font-mono uppercase tracking-wider">
              3. Model Certainty
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor:
                    result.confidence === 'high'
                      ? 'var(--status-success)'
                      : result.confidence === 'moderate'
                      ? 'var(--accent-cyan)'
                      : 'var(--status-uncertain)',
                }}
              />
              <span className="font-bold text-[var(--foreground)] capitalize">
                {result.evidenceCoverage === 'insufficient' || result.assessmentState === 'insufficient_information'
                  ? 'Indeterminate (Insufficient Evidence)'
                  : `${result.confidence} Certainty`}
              </span>
            </div>
          </div>
        </div>

        {/* Plain-Language Confidence & Uncertainty Rationale */}
        <div className="mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3.5 text-xs text-[var(--foreground-secondary)] leading-relaxed flex items-start gap-2.5">
          <Info className="h-4 w-4 text-[var(--accent-cyan)] shrink-0 mt-0.5" />
          <div>
            <strong className="text-[var(--foreground)]">Evaluation Rationale: </strong>
            <span>{result.confidenceRationale}</span>
          </div>
        </div>

        {/* Dedicated BEC / Payment-Redirection / Verification Advisory Banner */}
        {result.paymentChangeDetection?.detected && (
          <div
            className={`mt-4 rounded-xl border p-4 space-y-1.5 ${
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
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span>
                {result.paymentChangeDetection.isActiveRedirectionRequest
                  ? 'Active Bank-Account Change / Payment Redirection Detected (BEC Risk)'
                  : result.paymentChangeDetection.isVerificationRequest
                  ? 'Bank-Account Change Verification Request (Confirm via Established Records)'
                  : 'Unverified Bank-Account Change Notice Detected'}
              </span>
            </div>
            <p className="text-xs text-[var(--foreground)] leading-relaxed">
              {result.paymentChangeDetection.rationale}
            </p>
          </div>
        )}

        {/* Separated 3-Dimension Security & Verification Assessment */}
        {result.threatAssessment && result.factualVerification && result.authenticityAssessment && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-2.5">
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
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
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
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
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-3.5 space-y-1">
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

        {/* 1. Plain-Language Executive Explanation */}
        <div className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-5">
          <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--accent-cyan)]">
            Plain-Language Explanation
          </h4>
          <p className="mt-2 text-sm sm:text-base leading-relaxed text-[var(--foreground)] whitespace-pre-line">
            {result.summary}
          </p>
        </div>

        {/* 2. Specific Supporting Evidence & Warning Signs */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-[var(--primary-orange)]" />
              <span>Concrete Supporting Evidence ({result.indicators.length})</span>
            </h4>
            <span className="text-xs text-[var(--muted-foreground)] font-mono">
              {result.indicators.length > 0 ? 'Exact extracts from submission' : 'No adversarial cues'}
            </span>
          </div>

          {result.indicators.length > 0 ? (
            <div className="space-y-3">
              {result.indicators.map((item, index) => (
                <div
                  key={index}
                  className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-4 transition-colors hover:border-[var(--primary-orange)]/30"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-md bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[11px] font-mono font-bold text-[var(--accent-cyan)]">
                      {index + 1}
                    </span>
                    <h5 className="text-sm font-bold text-[var(--foreground)] tracking-tight">
                      {item.name}
                    </h5>
                  </div>

                  {/* Supporting text quote */}
                  {item.evidence && (
                    <div className="mt-2.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3.5 py-2 font-mono text-xs text-[var(--foreground)] break-words">
                      <span className="text-[var(--primary-orange)] font-bold select-none">&ldquo;</span>
                      {item.evidence}
                      <span className="text-[var(--primary-orange)] font-bold select-none">&rdquo;</span>
                    </div>
                  )}

                  {/* Reason why it matters */}
                  {item.reason && (
                    <p className="mt-2.5 text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
                      <strong className="text-[var(--foreground)]">Why it matters: </strong>
                      {item.reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--status-success-border)] bg-[var(--status-success-bg)] p-5 text-[var(--foreground-secondary)]">
              <div className="flex items-center gap-2.5 text-[var(--status-success)] font-semibold text-sm">
                <CheckCircle2 className="h-5 w-5" />
                <span>No Concrete Malicious Indicators Identified</span>
              </div>
              <p className="mt-2 text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
                The analysis engine scanned the text for coercive urgency, deceptive hyperlinks, spoofed identities, and suspicious payment requests. No adversarial markers or social-engineering vectors were detected.
              </p>
            </div>
          )}
        </div>

        {/* 3. Actionable Defense Checklist with State Controls */}
        <div className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 border-b border-[var(--border-subtle)] pb-3">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-[var(--status-success)]" />
                <span>Actionable Safety Checklist</span>
              </h4>
              <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
                Recommended steps relevant to detected threat indicators. Check off items as completed.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono font-semibold text-[var(--accent-cyan)] bg-[var(--surface)] border border-[var(--border)] px-2.5 py-1 rounded-md tabular-nums">
                {completedCount} of {totalActions} Done ({progressPercent}%)
              </span>
              <button
                type="button"
                onClick={() => handleMarkAllActions(completedCount !== totalActions)}
                className="text-[11px] font-medium text-[var(--foreground-secondary)] hover:text-[var(--primary-orange)] underline underline-offset-2 transition-colors cursor-pointer"
              >
                {completedCount === totalActions ? 'Reset' : 'Check all'}
              </button>
            </div>
          </div>

          {/* Checklist progress bar */}
          <div className="w-full bg-[var(--border)] rounded-full h-1.5 mb-4 overflow-hidden">
            <div
              className="bg-[var(--status-success)] h-1.5 transition-all duration-300 rounded-full"
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          <div className="space-y-2.5">
            {result.recommendedActions.map((action, index) => {
              const isChecked = !!completedActions[index];
              return (
                <button
                  key={index}
                  type="button"
                  onClick={() => toggleAction(index)}
                  className={`w-full text-left flex items-start gap-3 p-3.5 rounded-xl border transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none min-h-[44px] ${
                    isChecked
                      ? 'border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[var(--muted-foreground)]'
                      : 'border-[var(--border)] bg-[var(--surface)] hover:border-[var(--primary-orange)]/40 text-[var(--foreground)]'
                  }`}
                >
                  <div className="mt-0.5 shrink-0">
                    {isChecked ? (
                      <CheckSquare className="h-5 w-5 text-[var(--status-success)]" />
                    ) : (
                      <Square className="h-5 w-5 text-[var(--muted-foreground)]" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <span
                      className={`text-sm font-medium leading-relaxed ${
                        isChecked ? 'line-through text-[var(--muted-foreground)]' : 'text-[var(--foreground)]'
                      }`}
                    >
                      {action}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Finance & Accounts Payable Verification Guidance (for Payment Redirection / BEC / Payroll threats) */}
        {result.financeRecommendations &&
          result.financeRecommendations.length > 0 &&
          (result.paymentChangeDetection?.detected ||
            result.primaryThreatCategory === 'executive_impersonation' ||
            result.primaryThreatCategory === 'payroll_diversion') && (
            <div className="mt-6 rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-4 sm:p-5">
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert className="h-4 w-4 text-[var(--status-warning)]" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--status-warning)]">
                  Finance &amp; Accounts Payable Verification Controls
                </h4>
              </div>
              <ul className="space-y-1.5 text-xs text-[var(--foreground)] pl-5 list-disc">
                {result.financeRecommendations.map((rec, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

        {/* 4. Limitations & Uncertainty Notice */}
        <div className="mt-6 rounded-xl border border-[var(--accent-cyan)]/25 bg-[var(--accent-cyan-subtle)] p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-2">
            <Info className="h-4 w-4 text-[var(--accent-cyan)]" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--accent-cyan)]">
              Limitations &amp; Uncertainty Notice
            </h4>
          </div>
          <ul className="space-y-1.5 text-xs text-[var(--foreground-secondary)] pl-5 list-disc">
            {result.limitations.map((lim, index) => (
              <li key={index} className="leading-relaxed">
                {lim}
              </li>
            ))}
          </ul>
        </div>

        {/* Footer Meta: Engine identity and generation timestamp */}
        <div className="mt-5 flex flex-wrap items-center justify-between text-[11px] text-[var(--muted-foreground)] font-mono border-t border-[var(--border-subtle)] pt-3">
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5 text-[var(--accent-cyan)]" />
            <span>Intelligence: Aegis AI</span>
          </div>
          {result.analyzedAt && (
            <div className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              <span>Generated: {result.analyzedAt}</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
