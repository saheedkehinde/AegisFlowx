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
  ExternalLink,
} from 'lucide-react';
import { ScamAnalysisResult, RiskLevel } from '@/lib/scam-analyzer';

interface AnalysisResultProps {
  result: ScamAnalysisResult;
  onReset: () => void;
}

export default function AnalysisResult({ result, onReset }: AnalysisResultProps) {
  const [completedActions, setCompletedActions] = useState<Record<number, boolean>>({});
  const [copied, setCopied] = useState(false);

  const toggleAction = (index: number) => {
    setCompletedActions((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const handleCopyReport = () => {
    const reportText = `[ScamShield AI Security Advisory — Powered by Featherless AI]
Risk Level: ${result.riskLevel.toUpperCase()}
Model: ${result.model || 'Qwen/Qwen2.5-7B-Instruct'}
Analyzed At: ${result.analyzedAt || 'N/A'}

EXECUTIVE SUMMARY:
${result.summary}

EVIDENCE & WARNING SIGNS (${result.indicators.length}):
${result.indicators
  .map(
    (item, idx) =>
      `${idx + 1}. [${item.name}]
   Evidence: "${item.evidence}"
   Reason: ${item.reason}`
  )
  .join('\n\n')}

RECOMMENDED DEFENSIVE ACTIONS:
${result.recommendedActions.map((action, idx) => `${idx + 1}. ${action}`).join('\n')}

LIMITATIONS & UNCERTAINTIES:
${result.limitations.map((lim, idx) => `- ${lim}`).join('\n')}
`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  // Badge configuration based on Risk Level (normalized to lowercase)
  const getRiskBadgeConfig = (level: RiskLevel) => {
    switch (level) {
      case 'high':
        return {
          icon: AlertOctagon,
          label: 'HIGH RISK',
          subLabel: 'Critical scam or threat indicators detected',
          borderClass: 'border-red-500/40',
          bgClass: 'bg-red-950/20',
          textClass: 'text-red-400',
          glowClass: 'shadow-red-950/50',
          accentBg: 'bg-red-500/20 text-red-300 border-red-500/40',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          label: 'MEDIUM RISK',
          subLabel: 'Suspicious elements warranting heightened caution',
          borderClass: 'border-amber-500/40',
          bgClass: 'bg-amber-950/20',
          textClass: 'text-amber-400',
          glowClass: 'shadow-amber-950/50',
          accentBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        };
      case 'low':
        return {
          icon: ShieldCheck,
          label: 'LOW RISK',
          subLabel: 'No blatant fraud or social engineering markers found',
          borderClass: 'border-emerald-500/40',
          bgClass: 'bg-emerald-950/20',
          textClass: 'text-emerald-400',
          glowClass: 'shadow-emerald-950/50',
          accentBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        };
      case 'uncertain':
      default:
        return {
          icon: ShieldQuestion,
          label: 'UNCERTAIN',
          subLabel: 'Insufficient evidence to reach a conclusive judgment',
          borderClass: 'border-purple-500/40',
          bgClass: 'bg-purple-950/20',
          textClass: 'text-purple-400',
          glowClass: 'shadow-purple-950/50',
          accentBg: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
        };
    }
  };

  const badgeConfig = getRiskBadgeConfig(result.riskLevel);
  const RiskIcon = badgeConfig.icon;

  const totalActions = result.recommendedActions.length;
  const completedCount = Object.values(completedActions).filter(Boolean).length;

  return (
    <section id="results-section" className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 mt-10">
      <div
        className={`relative overflow-hidden rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.bgClass} p-5 sm:p-8 shadow-2xl ${badgeConfig.glowClass} backdrop-blur-xl transition-all`}
      >
        {/* Top Header: Badge, Threat Classification & Engine Info */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-white/10 pb-5">
          <div className="flex items-center gap-4">
            {/* Risk Badge Icon Box */}
            <div
              className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border ${badgeConfig.borderClass} ${badgeConfig.accentBg} shadow-lg`}
            >
              <RiskIcon className="h-7 w-7" />
            </div>

            <div>
              <div className="flex items-center gap-2.5">
                <span className={`text-xl sm:text-2xl font-black tracking-tight ${badgeConfig.textClass}`}>
                  {badgeConfig.label}
                </span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded border border-white/10 bg-white/5 text-slate-300">
                  Model Assessment
                </span>
              </div>
              <p className="mt-0.5 text-xs sm:text-sm text-slate-300">
                {badgeConfig.subLabel}
              </p>
            </div>
          </div>

          {/* Action & Metadata */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleCopyReport}
              type="button"
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:border-blue-500/30 transition-colors cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Advisory Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 text-slate-400" />
                  <span>Copy Advisory</span>
                </>
              )}
            </button>

            <button
              onClick={onReset}
              type="button"
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:border-blue-500/30 transition-colors cursor-pointer"
            >
              <span>Analyze Another</span>
            </button>
          </div>
        </div>

        {/* Engine and Timestamp banner */}
        <div className="mt-3 flex flex-wrap items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5 text-blue-400" />
            <span>Featherless AI Model:</span>
            <span className="font-mono text-slate-200">
              {result.model || 'Qwen/Qwen2.5-7B-Instruct'}
            </span>
          </div>
          {result.analyzedAt && (
            <div className="flex items-center gap-1.5 text-slate-500 mt-1 sm:mt-0">
              <Clock className="h-3.5 w-3.5" />
              <span>Generated at {result.analyzedAt}</span>
            </div>
          )}
        </div>

        {/* 1. Plain-Language Summary */}
        <div className="mt-6 rounded-xl border border-white/10 bg-[#090d18]/80 p-4 sm:p-5">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Plain-Language Explanation
          </h4>
          <p className="mt-2 text-sm sm:text-base leading-relaxed text-slate-200 whitespace-pre-line">
            {result.summary}
          </p>
        </div>

        {/* 2. Warning Sign Indicators Cards */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-blue-400" />
              <span>Evidence & Warning Signs ({result.indicators.length})</span>
            </h4>
            <span className="text-xs text-slate-500">Concrete supporting evidence</span>
          </div>

          {result.indicators.length === 0 ? (
            <div className="rounded-xl border border-white/5 bg-[#090d18]/60 p-4 text-xs text-slate-400">
              No specific malicious indicators were identified in this message.
            </div>
          ) : (
            <div className="space-y-3">
              {result.indicators.map((item, index) => (
                <div
                  key={index}
                  className="rounded-xl border border-white/10 bg-slate-900/60 p-4 transition-colors hover:border-blue-500/25"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-500/20 text-[11px] font-mono text-blue-300">
                      {index + 1}
                    </span>
                    <h5 className="text-sm font-bold text-white tracking-tight">
                      {item.name}
                    </h5>
                  </div>

                  {/* Supporting text quote */}
                  {item.evidence && (
                    <div className="mt-2.5 rounded-lg border border-white/5 bg-[#060911] px-3.5 py-2 font-mono text-xs text-slate-300 break-words">
                      <span className="text-blue-400 font-bold select-none">&ldquo;</span>
                      {item.evidence}
                      <span className="text-blue-400 font-bold select-none">&rdquo;</span>
                    </div>
                  )}

                  {/* Explanation of why it matters */}
                  {item.reason && (
                    <p className="mt-2.5 text-xs sm:text-sm text-slate-300 leading-relaxed">
                      <strong className="text-slate-200">Why it matters: </strong>
                      {item.reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 3. Recommended Safety Actions Checklist */}
        <div className="mt-6 rounded-xl border border-white/10 bg-[#090d18]/80 p-4 sm:p-5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4 border-b border-white/5 pb-3">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>Recommended Practical Safety Actions</span>
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                Check off items as you complete these safety steps.
              </p>
            </div>
            {totalActions > 0 && (
              <div className="text-xs font-medium text-slate-400 bg-white/5 px-2.5 py-1 rounded-md self-start sm:self-auto">
                Completed {completedCount} of {totalActions}
              </div>
            )}
          </div>

          <div className="space-y-2.5">
            {result.recommendedActions.map((action, index) => {
              const isChecked = !!completedActions[index];
              return (
                <button
                  key={index}
                  type="button"
                  onClick={() => toggleAction(index)}
                  className={`w-full text-left flex items-start gap-3 p-3 rounded-xl border transition-all cursor-pointer ${
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
        <div className="mt-6 rounded-xl border border-blue-500/20 bg-blue-950/20 p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-2">
            <Info className="h-4 w-4 text-blue-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-blue-300">
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
      </div>
    </section>
  );
}
