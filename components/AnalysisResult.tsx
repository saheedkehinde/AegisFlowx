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
} from 'lucide-react';
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
    const reportText = `[ScamShield AI Incident Advisory — Qwen Threat Analysis]
Risk Level: ${result.riskLevel.toUpperCase()}
Evidence Depth: ${result.evidenceSufficiency.toUpperCase()}
Model Confidence: ${result.confidence.toUpperCase()}
Model: ${result.model || 'Qwen/Qwen3-VL-8B-Instruct'}
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
      '# ScamShield Extracted Defanged IOCs',
      `# Risk: ${result.riskLevel.toUpperCase()} | Model: ${result.model || 'Qwen3'}`,
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
          borderClass: 'border-red-500/40',
          bgClass: 'bg-red-950/20',
          textClass: 'text-red-400',
          accentBg: 'bg-red-500/20 text-red-300 border-red-500/40',
          badgePill: 'border-red-500/30 bg-red-950/50 text-red-300',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          label: 'MEDIUM RISK',
          subLabel: 'Suspicious coercive or anomalous elements detected',
          borderClass: 'border-amber-500/40',
          bgClass: 'bg-amber-950/20',
          textClass: 'text-amber-400',
          accentBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          badgePill: 'border-amber-500/30 bg-amber-950/50 text-amber-300',
        };
      case 'low':
        return {
          icon: ShieldCheck,
          label: 'LOW RISK',
          subLabel: 'No active fraud or social engineering markers detected',
          borderClass: 'border-emerald-500/40',
          bgClass: 'bg-emerald-950/20',
          textClass: 'text-emerald-400',
          accentBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          badgePill: 'border-emerald-500/30 bg-emerald-950/50 text-emerald-300',
        };
      case 'uncertain':
      default:
        return {
          icon: ShieldQuestion,
          label: 'UNCERTAIN',
          subLabel: 'Inconclusive telemetry: context is insufficient to determine intent',
          borderClass: 'border-purple-500/40',
          bgClass: 'bg-purple-950/20',
          textClass: 'text-purple-400',
          accentBg: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
          badgePill: 'border-purple-500/30 bg-purple-950/50 text-purple-300',
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
      className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 mt-10 outline-none"
    >
      <div
        className={`relative rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.bgClass} p-5 sm:p-8 shadow-2xl backdrop-blur-xl transition-all`}
      >
        {/* Top Header: Risk Classification & Quick Controls */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-5 border-b border-white/10 pb-6">
          <div className="flex items-start sm:items-center gap-4">
            {/* Risk Badge Icon Box */}
            <div
              className={`flex h-14 w-14 sm:h-16 sm:w-16 shrink-0 items-center justify-center rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.accentBg} shadow-lg`}
            >
              <RiskIcon className="h-7 w-7 sm:h-8 sm:w-8" />
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className={`text-2xl sm:text-3xl font-black tracking-tight ${badgeConfig.textClass}`}>
                  {badgeConfig.label}
                </span>
                <span className="text-xs font-mono font-medium px-2 py-0.5 rounded border border-white/10 bg-white/5 text-slate-300">
                  Severity Score: {result.severityScore ?? 50}/100
                </span>
              </div>
              <p className="mt-1 text-xs sm:text-sm text-slate-300">
                {badgeConfig.subLabel}
              </p>
            </div>
          </div>

          {/* Quick Action Buttons (Responsive & Accessible) */}
          <div className="flex flex-wrap items-center gap-2 pt-2 md:pt-0">
            <button
              onClick={handleCopyReport}
              type="button"
              className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/80 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white hover:border-cyan-500/40 transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="h-4 w-4 text-emerald-400" />
                  <span className="text-emerald-400 font-semibold">Advisory Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4 text-slate-400" />
                  <span>Copy Advisory</span>
                </>
              )}
            </button>

            {hasIOCs && (
              <button
                onClick={handleCopyDefangedIOCs}
                type="button"
                className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/80 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white hover:border-cyan-500/40 transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer"
              >
                {copiedIOCs ? (
                  <>
                    <Check className="h-4 w-4 text-cyan-400" />
                    <span className="text-cyan-400 font-semibold">IOCs Copied</span>
                  </>
                ) : (
                  <>
                    <Terminal className="h-4 w-4 text-cyan-400" />
                    <span>Copy Defanged IOCs</span>
                  </>
                )}
              </button>
            )}

            <button
              onClick={onReset}
              type="button"
              className="min-h-[40px] inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-3.5 py-2 text-xs font-medium text-cyan-300 hover:bg-cyan-900/50 hover:text-cyan-100 transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer"
            >
              <RotateCcw className="h-4 w-4 text-cyan-400" />
              <span>Analyze Another</span>
            </button>
          </div>
        </div>

        {/* Essential Cyber Telemetry: Distinguishing Risk, Sufficiency & Model Certainty */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
          <div className="rounded-xl border border-white/5 bg-[#090d18]/60 p-3 flex flex-col justify-between">
            <span className="text-slate-400 text-[11px] font-mono uppercase tracking-wider">
              1. Threat Severity
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${
                result.riskLevel === 'high' ? 'bg-red-400' : result.riskLevel === 'medium' ? 'bg-amber-400' : result.riskLevel === 'low' ? 'bg-emerald-400' : 'bg-purple-400'
              }`} />
              <span className="font-bold text-white uppercase">{result.riskLevel} Risk</span>
            </div>
          </div>

          <div className="rounded-xl border border-white/5 bg-[#090d18]/60 p-3 flex flex-col justify-between">
            <span className="text-slate-400 text-[11px] font-mono uppercase tracking-wider">
              2. Evidence Context Depth
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${
                result.evidenceSufficiency === 'sufficient' ? 'bg-cyan-400' : result.evidenceSufficiency === 'moderate' ? 'bg-amber-400' : 'bg-slate-400'
              }`} />
              <span className="font-bold text-white capitalize">{result.evidenceSufficiency} Context</span>
            </div>
          </div>

          <div className="rounded-xl border border-white/5 bg-[#090d18]/60 p-3 flex flex-col justify-between">
            <span className="text-slate-400 text-[11px] font-mono uppercase tracking-wider">
              3. Model Certainty
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${
                result.confidence === 'high' ? 'bg-emerald-400' : result.confidence === 'moderate' ? 'bg-cyan-400' : 'bg-purple-400'
              }`} />
              <span className="font-bold text-white capitalize">{result.confidence} Certainty</span>
            </div>
          </div>
        </div>

        {/* Plain-Language Confidence & Uncertainty Rationale */}
        <div className="mt-3 rounded-xl border border-white/5 bg-slate-900/40 p-3.5 text-xs text-slate-300 leading-relaxed flex items-start gap-2.5">
          <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <strong className="text-cyan-200">Evaluation Rationale: </strong>
            <span>{result.confidenceRationale}</span>
          </div>
        </div>

        {/* 1. Plain-Language Executive Explanation */}
        <div className="mt-6 rounded-xl border border-white/10 bg-[#090d18]/85 p-5">
          <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            Plain-Language Explanation
          </h4>
          <p className="mt-2 text-sm sm:text-base leading-relaxed text-slate-200 whitespace-pre-line">
            {result.summary}
          </p>
        </div>

        {/* 2. Specific Supporting Evidence & Warning Signs */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-cyan-400" />
              <span>Concrete Supporting Evidence ({result.indicators.length})</span>
            </h4>
            <span className="text-xs text-slate-500 font-mono">
              {result.indicators.length > 0 ? 'Exact extracts from submission' : 'No adversarial cues'}
            </span>
          </div>

          {result.indicators.length > 0 ? (
            <div className="space-y-3">
              {result.indicators.map((item, index) => (
                <div
                  key={index}
                  className="rounded-xl border border-white/10 bg-slate-900/60 p-4 transition-colors hover:border-cyan-500/25"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-500/20 text-[11px] font-mono text-cyan-300">
                      {index + 1}
                    </span>
                    <h5 className="text-sm font-bold text-white tracking-tight">
                      {item.name}
                    </h5>
                  </div>

                  {/* Supporting text quote */}
                  {item.evidence && (
                    <div className="mt-2.5 rounded-lg border border-white/5 bg-[#060911] px-3.5 py-2 font-mono text-xs text-slate-300 break-words">
                      <span className="text-cyan-400 font-bold select-none">&ldquo;</span>
                      {item.evidence}
                      <span className="text-cyan-400 font-bold select-none">&rdquo;</span>
                    </div>
                  )}

                  {/* Reason why it matters */}
                  {item.reason && (
                    <p className="mt-2.5 text-xs sm:text-sm text-slate-300 leading-relaxed">
                      <strong className="text-slate-200">Why it matters: </strong>
                      {item.reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/15 p-5 text-slate-300">
              <div className="flex items-center gap-2.5 text-emerald-400 font-semibold text-sm">
                <CheckCircle2 className="h-5 w-5" />
                <span>No Concrete Malicious Indicators Identified</span>
              </div>
              <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
                The analysis engine scanned the text for coercive urgency, deceptive hyperlinks, spoofed identities, and suspicious payment requests. No adversarial markers or social-engineering vectors were detected.
              </p>
            </div>
          )}
        </div>

        {/* 3. Actionable Defense Checklist with State Controls */}
        <div className="mt-6 rounded-xl border border-white/10 bg-[#090d18]/85 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 border-b border-white/5 pb-3">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>Actionable Safety Checklist</span>
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                Recommended steps relevant to detected threat indicators. Check off items as completed.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono font-medium text-cyan-300 bg-white/5 px-2.5 py-1 rounded-md">
                {completedCount} of {totalActions} Done ({progressPercent}%)
              </span>
              <button
                type="button"
                onClick={() => handleMarkAllActions(completedCount !== totalActions)}
                className="text-[11px] text-slate-400 hover:text-cyan-300 underline underline-offset-2 transition-colors cursor-pointer"
              >
                {completedCount === totalActions ? 'Reset' : 'Check all'}
              </button>
            </div>
          </div>

          {/* Checklist progress bar */}
          <div className="w-full bg-slate-800 rounded-full h-1.5 mb-4 overflow-hidden">
            <div
              className="bg-emerald-500 h-1.5 transition-all duration-300 rounded-full"
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
                  className={`w-full text-left flex items-start gap-3 p-3.5 rounded-xl border transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none min-h-[44px] ${
                    isChecked
                      ? 'border-emerald-500/30 bg-emerald-950/20 text-slate-400'
                      : 'border-white/5 bg-slate-900/50 hover:border-white/15 text-slate-200'
                  }`}
                >
                  <div className="mt-0.5 shrink-0 text-slate-400 hover:text-white">
                    {isChecked ? (
                      <CheckSquare className="h-5 w-5 text-emerald-400" />
                    ) : (
                      <Square className="h-5 w-5 text-slate-500" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <span
                      className={`text-sm font-medium leading-relaxed ${
                        isChecked ? 'line-through text-slate-400' : 'text-slate-100'
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

        {/* 4. Limitations & Uncertainty Notice */}
        <div className="mt-6 rounded-xl border border-cyan-500/20 bg-cyan-950/15 p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-2">
            <Info className="h-4 w-4 text-cyan-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
              Limitations &amp; Uncertainty Notice
            </h4>
          </div>
          <ul className="space-y-1.5 text-xs text-slate-300 pl-5 list-disc">
            {result.limitations.map((lim, index) => (
              <li key={index} className="leading-relaxed">
                {lim}
              </li>
            ))}
          </ul>
        </div>

        {/* Footer Meta: Model name and generation timestamp */}
        <div className="mt-5 flex flex-wrap items-center justify-between text-[11px] text-slate-500 font-mono border-t border-white/5 pt-3">
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5 text-cyan-400" />
            <span>Model: {result.model || 'Qwen/Qwen3-VL-8B-Instruct'}</span>
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
