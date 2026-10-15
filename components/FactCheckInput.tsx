'use client';

import React, { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  Sparkles,
  Loader2,
  AlertCircle,
  FileCheck2,
  ShieldAlert,
  HelpCircle,
  ExternalLink,
  Info,
  KeyRound,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { FactCheckReport } from '@/lib/fact-checker/types';

interface FactCheckInputProps {
  onReportComplete: (report: FactCheckReport) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  initialText?: string;
}

export default function FactCheckInput({
  onReportComplete,
  isLoading,
  setIsLoading,
  initialText = '',
}: FactCheckInputProps) {
  const [text, setText] = useState<string>(() => {
    if (initialText) return initialText;
    if (typeof window !== 'undefined') {
      const preloaded = sessionStorage.getItem('aegisflow_factcheck_preload');
      if (preloaded) {
        sessionStorage.removeItem('aegisflow_factcheck_preload');
        return preloaded;
      }
    }
    return '';
  });
  const [error, setError] = useState<string | null>(null);
  const [showConfigGuide, setShowConfigGuide] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim() || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/fact-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text.trim() }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error || `Fact-check request failed with status ${res.status}`);
      }

      if (!data?.report) {
        throw new Error('Server returned an empty fact-check report.');
      }

      onReportComplete(data.report);
    } catch (err: any) {
      setError(err?.message || 'Failed to complete web research fact check.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadSample = (type: 'bank' | 'invoice' | 'crypto' | 'conversational') => {
    if (type === 'bank') {
      setText(
        'WELLS FARGO ALERT: An unauthorized debit of $1,429.99 was flagged on your account. To dispute this charge and avoid an account freeze, verify identity within 15 minutes at https://wf-secure-verify.com or call our fraud department.'
      );
    } else if (type === 'invoice') {
      setText(
        'INVOICE #9410 from Geek Squad Best Buy: Your annual auto-renewal subscription of $499.99 will be charged to your checking account today. To cancel or request a full refund, contact customer support immediately at +1-800-555-0199.'
      );
    } else if (type === 'crypto') {
      setText(
        'IRS Tax Refund Notice: You have an unclaimed federal tax refund of $820.00 from 2025. Submit your direct deposit routing number and SSN at https://irs-tax-refund-portal.gov.us.org within 24 hours to claim.'
      );
    } else {
      // Non-verifiable conversational greeting
      setText('Hello, can you attend to me? I wanted to ask how you are doing today.');
    }
    setError(null);
  };

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-cyan-500/30 bg-[#0d1322] p-5 sm:p-7 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/40 px-2.5 py-0.5 text-[10px] font-mono text-cyan-300 font-semibold mb-1.5">
              <Globe className="h-3 w-3 text-cyan-400" />
              <span>Evidence-Based Web Research &amp; Fact-Checking</span>
            </span>
            <h3 className="text-lg font-bold text-white">
              Investigate Claims, Communications, Invoices &amp; URLs
            </h3>
            <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Dissects factual claims from opinions, retrieves public web evidence, interrogates authoritative DNS records, and provides verifiable source citations.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setShowConfigGuide(!showConfigGuide)}
            className="self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 px-2.5 py-1.5 rounded-lg border border-cyan-500/30 transition-colors cursor-pointer"
          >
            <KeyRound className="h-3.5 w-3.5" />
            <span>Search &amp; Intel Setup</span>
            {showConfigGuide ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        </div>

        {/* Collapsible Search Provider Setup Guide */}
        {showConfigGuide && (
          <div className="rounded-xl border border-cyan-500/30 bg-[#090d18] p-4 text-xs space-y-3 animate-fadeIn">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <h5 className="font-semibold text-white">Configuring Research &amp; Threat Intelligence Providers</h5>
                <p className="text-slate-300 text-[11px] mt-1 leading-relaxed">
                  AegisFlow supports modular server-side search and threat-intel integrations. When API keys are not provided, it operates cleanly in <strong>Wikimedia Registry + Open Web Fallback</strong> mode.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              <div className="rounded-lg bg-black/40 border border-cyan-500/20 p-3 space-y-1">
                <span className="text-[10px] font-mono text-cyan-400 block font-semibold">SERPER_API_KEY (Web Search)</span>
                <p className="text-[11px] text-slate-300">
                  Enables live Google Search results via Serper.dev API with structured evidence and excerpts.
                </p>
                <a
                  href="https://serper.dev"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-cyan-400 hover:underline inline-flex items-center gap-1 pt-1"
                >
                  <span>serper.dev (2,500 free queries)</span>
                  <ExternalLink className="h-2.5 w-2.5" />
                </a>
              </div>

              <div className="rounded-lg bg-black/40 border border-purple-500/20 p-3 space-y-1">
                <span className="text-[10px] font-mono text-purple-400 block font-semibold">URLHAUS_AUTH_KEY (Malware Intel)</span>
                <p className="text-[11px] text-slate-300">
                  Queries abuse.ch URLhaus database for active malware and phishing distribution infrastructure.
                </p>
                <a
                  href="https://auth.abuse.ch"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-purple-400 hover:underline inline-flex items-center gap-1 pt-1"
                >
                  <span>auth.abuse.ch (Free Auth-Key)</span>
                  <ExternalLink className="h-2.5 w-2.5" />
                </a>
              </div>
            </div>
          </div>
        )}

        {/* Quick Sample Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-slate-500">Preset Scenarios:</span>
          <button
            type="button"
            onClick={() => loadSample('bank')}
            className="rounded-lg border border-white/5 bg-slate-900/60 px-2.5 py-1 text-[11px] text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            🏦 Wells Fargo Wire Alert
          </button>
          <button
            type="button"
            onClick={() => loadSample('invoice')}
            className="rounded-lg border border-white/5 bg-slate-900/60 px-2.5 py-1 text-[11px] text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            📄 Geek Squad Renewal Invoice
          </button>
          <button
            type="button"
            onClick={() => loadSample('crypto')}
            className="rounded-lg border border-white/5 bg-slate-900/60 px-2.5 py-1 text-[11px] text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            🏛️ IRS Refund Phishing Notice
          </button>
          <button
            type="button"
            onClick={() => loadSample('conversational')}
            className="rounded-lg border border-purple-500/30 bg-purple-950/20 px-2.5 py-1 text-[11px] text-purple-300 hover:text-white hover:bg-purple-900/40 transition-colors cursor-pointer"
          >
            💬 Conversational Greeting (Non-Factual)
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste suspicious message, invoice claim, email body, URL, or public assertion to cross-examine against public evidence..."
              rows={5}
              disabled={isLoading}
              className="w-full rounded-xl border border-white/10 bg-[#090d18] p-4 text-xs sm:text-sm text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 font-mono transition-all resize-y"
            />
            <div className="flex items-center justify-between mt-1.5 text-[11px] text-slate-500 font-mono">
              <span>{text.length} / 6,000 characters</span>
              <span>Primary evidence prioritizes official advisories &amp; DNS telemetry</span>
            </div>
          </div>

          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-300 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
            <span className="text-[11px] text-slate-400">
              Untrusted URLs are never visited automatically. SSRF defenses strictly enforced.
            </span>

            <button
              type="submit"
              disabled={isLoading || !text.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-6 py-2.5 text-xs sm:text-sm font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Researching Evidence Across Web...</span>
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  <span>Execute Evidence-Based Fact-Check</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
