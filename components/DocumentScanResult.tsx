'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  AlertCircle,
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
  FileText,
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
  ExternalLink,
  Shield,
  FileCheck,
  Eye,
  Globe,
} from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';
import { DocumentScanResult } from '@/lib/document-scanner';
import { RiskLevel } from '@/lib/scam-analyzer';

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

  const toggleAction = (idx: number) => {
    setCompletedActions((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const getRiskBadge = (risk: RiskLevel) => {
    switch (risk) {
      case 'high':
        return {
          label: 'HIGH THREAT RISK',
          color: 'text-red-400 bg-red-950/50 border-red-500/40',
          icon: AlertOctagon,
          desc: 'Critical indicators of fraud, phishing, or credential harvesting detected.',
        };
      case 'medium':
        return {
          label: 'SUSPICIOUS / ELEVATED RISK',
          color: 'text-amber-400 bg-amber-950/50 border-amber-500/40',
          icon: AlertTriangle,
          desc: 'Multiple anomalous patterns detected. Independent verification recommended.',
        };
      case 'low':
        return {
          label: 'LOW OBSERVED RISK',
          color: 'text-emerald-400 bg-emerald-950/50 border-emerald-500/40',
          icon: ShieldCheck,
          desc: 'No urgent pressure or malicious patterns identified in visible content.',
        };
      case 'uncertain':
      default:
        return {
          label: 'UNCERTAIN / INSUFFICIENT EVIDENCE',
          color: 'text-purple-400 bg-purple-950/50 border-purple-500/40',
          icon: ShieldQuestion,
          desc: 'Document text is sparse or ambiguous. Do not assume authenticity.',
        };
    }
  };

  const badge = getRiskBadge(result.riskLevel);
  const RiskIcon = badge.icon;

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

Assessed by AegisFlow (Model: ${result.model || 'Qwen3-VL-8B'}) at ${result.analyzedAt}`;

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
      <div className="rounded-2xl border border-white/5 bg-[#0d1322] p-5 sm:p-7 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 border-b border-white/5 pb-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <ThreatBadge
                level={result.riskLevel}
                score={result.severityScore}
                showScore={true}
                size="md"
              />
              <span className="rounded-lg bg-slate-900 border border-white/5 px-2.5 py-1 text-[11px] font-mono text-slate-400 capitalize">
                Confidence: {result.confidence}
              </span>
            </div>
            <h3 className="text-xl sm:text-2xl font-extrabold text-white">
              Document Threat Analysis Report
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-3xl">
              {result.summary}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-start lg:self-center shrink-0">
            <button
              type="button"
              onClick={handleCopyReport}
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-slate-900/80 hover:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:text-white transition-colors cursor-pointer"
            >
              {copiedReport ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-cyan-400" />}
              <span>{copiedReport ? 'Copied' : 'Copy Report'}</span>
            </button>
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-1.5 rounded-xl border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/50 px-3.5 py-2 text-xs font-semibold text-cyan-300 transition-colors cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Scan Another Document</span>
            </button>
          </div>
        </div>

        {/* SECTION 1: WHAT THE DOCUMENT ACTUALLY CONTAINS */}
        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              <span>1. What The Document Actually Contains</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-400">
              {result.documentContent.filename}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-[10px] uppercase font-bold text-slate-400">Detected Category</span>
              <p className="mt-1 text-xs font-semibold text-white capitalize">
                {result.documentContent.detectedType.replace('_', ' ')}
              </p>
            </div>
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-[10px] uppercase font-bold text-slate-400">Stated Sender / Organization</span>
              <p className="mt-1 text-xs font-semibold text-cyan-300 truncate">
                {result.documentContent.apparentSenderOrOrganization || 'Not explicitly stated'}
              </p>
            </div>
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-[10px] uppercase font-bold text-slate-400">Claimed Purpose</span>
              <p className="mt-1 text-xs font-semibold text-slate-200 truncate">
                {result.documentContent.claimedPurpose || 'Information request'}
              </p>
            </div>
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-3.5">
              <span className="text-[10px] uppercase font-bold text-slate-400">File Type &amp; Size</span>
              <p className="mt-1 text-xs font-mono text-slate-300">
                {result.documentContent.mimeType} ({(result.documentContent.fileSizeBytes / 1024).toFixed(1)} KB)
                {result.documentContent.pageCount ? ` &middot; ${result.documentContent.pageCount}p` : ''}
              </p>
            </div>
          </div>

          {/* Extracted Text Snippet */}
          {result.documentContent.extractedTextSnippet && (
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 space-y-2">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span className="font-semibold text-slate-300">Extracted Text Content (Untrusted Evidence):</span>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(result.documentContent.extractedTextSnippet);
                    setCopiedSnippet(true);
                    setTimeout(() => setCopiedSnippet(false), 2000);
                  }}
                  className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer"
                >
                  {copiedSnippet ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  <span>{copiedSnippet ? 'Copied' : 'Copy Text'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap break-words max-h-36 overflow-y-auto bg-black/40 p-3 rounded-lg border border-white/5">
                {result.documentContent.extractedTextSnippet}
              </pre>
            </div>
          )}
        </div>

        {/* SECTION 2: WHAT APPEARS SUSPICIOUS */}
        <div className="mt-8 space-y-4 border-t border-white/5 pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              <span>2. What Appears Suspicious (Threat Indicators)</span>
            </h4>
            <span className="text-[11px] font-mono text-amber-400">
              {result.indicators.length + (result.suspiciousElements?.length || 0)} Anomalies Detected
            </span>
          </div>

          {result.suspiciousElements && result.suspiciousElements.length > 0 ? (
            <div className="space-y-2.5">
              {result.suspiciousElements.map((el, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-3.5 space-y-1.5"
                >
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-amber-950/80 border border-amber-500/30 px-2 py-0.5 text-[10px] font-mono font-bold text-amber-300 uppercase">
                      {el.category.replace('_', ' ')}
                    </span>
                    <p className="text-xs font-semibold text-white">{el.explanation}</p>
                  </div>
                  {el.evidence && (
                    <p className="text-xs font-mono text-amber-200/90 pl-3 border-l-2 border-amber-500/40">
                      &quot;{el.evidence}&quot;
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : result.indicators.length > 0 ? (
            <div className="space-y-2.5">
              {result.indicators.map((ind, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-3.5 space-y-1"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">{ind.name}</span>
                  </div>
                  <p className="text-xs text-slate-300">{ind.reason}</p>
                  {ind.evidence && (
                    <p className="text-xs font-mono text-amber-200/80 pl-3 border-l-2 border-amber-500/40">
                      &quot;{ind.evidence}&quot;
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 text-xs text-slate-400 text-center">
              No obvious coercive manipulation or phishing indicators identified in visible text.
            </div>
          )}
        </div>

        {/* SECTION 3: WHAT HAS OR HAS NOT BEEN INDEPENDENTLY VERIFIED */}
        <div className="mt-8 space-y-4 border-t border-white/5 pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FileCheck className="h-4 w-4 text-cyan-400" />
              <span>3. Independent Verification Status</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-400">Zero Unverified Trust</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Unverified Claims */}
            <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-red-300">
                <AlertCircle className="h-4 w-4" />
                <span>Unverified Claims (Do Not Assume Legitimate)</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                {result.verificationStatus.unverifiedClaims.map((claim, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {claim}
                  </li>
                ))}
              </ul>
            </div>

            {/* Verified Elements */}
            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-cyan-300">
                <CheckCircle2 className="h-4 w-4" />
                <span>Independently Verified Elements</span>
              </div>
              {result.verificationStatus.independentlyVerified.length > 0 ? (
                <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                  {result.verificationStatus.independentlyVerified.map((v, idx) => (
                    <li key={idx}>{v}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400 leading-relaxed">
                  No claims or senders are verified. Automated AI inspection cannot confirm company authorization, banking ownership, or external DNS certificates.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* SECTION 4: WHAT THE USER SHOULD DO NEXT */}
        <div className="mt-8 space-y-4 border-t border-white/5 pt-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span>4. Recommended Next Steps (Action Checklist)</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-400">
              {Object.values(completedActions).filter(Boolean).length} of {result.recommendedActions.length} completed
            </span>
          </div>

          <div className="space-y-2">
            {result.recommendedActions.map((action, idx) => {
              const isDone = completedActions[idx];
              return (
                <button
                  key={idx}
                  type="button"
                  onClick={() => toggleAction(idx)}
                  className={`w-full flex items-start gap-3 rounded-xl border p-3.5 text-left transition-all cursor-pointer ${
                    isDone
                      ? 'border-emerald-500/30 bg-emerald-950/20 text-slate-400 line-through'
                      : 'border-white/5 bg-[#090d18] hover:border-cyan-500/30 text-white'
                  }`}
                >
                  {isDone ? (
                    <CheckSquare className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                  ) : (
                    <Square className="h-4 w-4 text-slate-500 mt-0.5 shrink-0" />
                  )}
                  <span className="text-xs font-medium leading-relaxed">{action}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* SECTION 5: EXTRACTED INDICATORS OF COMPROMISE (IOCs) */}
        {totalIocsCount > 0 && (
          <div className="mt-8 space-y-4 border-t border-white/5 pt-6">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Link2 className="h-4 w-4 text-cyan-400" />
                <span>Extracted Indicators of Compromise (IOC Vault)</span>
              </h4>
              <button
                type="button"
                onClick={handleCopyIOCs}
                className="text-[11px] font-medium text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer"
              >
                {copiedIOCs ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                <span>{copiedIOCs ? 'Copied' : 'Copy All IOCs'}</span>
              </button>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 space-y-3">
              <p className="text-[11px] text-amber-400/90 flex items-center gap-1.5">
                <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                <span>Security Notice: URLs and email addresses extracted from untrusted materials are never automatically visited.</span>
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                {result.iocs?.urls && result.iocs.urls.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400">Extracted URLs</span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {result.iocs.urls.map((u, i) => (
                        <div key={i} className="text-xs font-mono text-cyan-300 truncate bg-slate-900/60 p-1.5 rounded border border-white/5">
                          {u}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.iocs?.emails && result.iocs.emails.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400">Extracted Emails</span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {result.iocs.emails.map((e, i) => (
                        <div key={i} className="text-xs font-mono text-purple-300 truncate bg-slate-900/60 p-1.5 rounded border border-white/5">
                          {e}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.iocs?.phoneNumbers && result.iocs.phoneNumbers.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400">Extracted Phone Numbers</span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {result.iocs.phoneNumbers.map((p, i) => (
                        <div key={i} className="text-xs font-mono text-emerald-300 truncate bg-slate-900/60 p-1.5 rounded border border-white/5">
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
        <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-5 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            <span>Inference Model: <strong className="text-slate-200">{result.model || 'Qwen3-VL-8B'}</strong></span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/analyze?tab=factcheck"
              onClick={() => {
                if (typeof window !== 'undefined' && result.documentContent.extractedTextSnippet) {
                  sessionStorage.setItem('aegisflow_factcheck_preload', result.documentContent.extractedTextSnippet);
                }
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/60 px-3 py-1.5 text-xs font-semibold text-cyan-300 transition-colors"
            >
              <Globe className="h-3.5 w-3.5" />
              <span>Fact-Check Claims</span>
            </Link>

            <Link
              href="/investigations"
              className="text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1 transition-colors"
            >
              <span>View in Investigation Vault</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
