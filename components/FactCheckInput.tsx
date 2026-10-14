'use client';

import React, { useState } from 'react';
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
} from 'lucide-react';
import { FactCheckReport } from '@/lib/fact-checker/types';

interface FactCheckInputProps {
  onReportComplete: (report: FactCheckReport) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export default function FactCheckInput({
  onReportComplete,
  isLoading,
  setIsLoading,
}: FactCheckInputProps) {
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);

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

  const loadSample = (type: 'bank' | 'invoice' | 'crypto') => {
    if (type === 'bank') {
      setText(
        'WELLS FARGO ALERT: An unauthorized debit of $1,429.99 was flagged on your account. To dispute this charge and avoid an account freeze, verify identity within 15 minutes at https://wf-secure-verify.com or call our fraud department.'
      );
    } else if (type === 'invoice') {
      setText(
        'INVOICE #9410 from Geek Squad Best Buy: Your annual auto-renewal subscription of $499.99 will be charged to your checking account today. To cancel or request a full refund, contact customer support immediately at +1-800-555-0199.'
      );
    } else {
      setText(
        'IRS Tax Refund Notice: You have an unclaimed federal tax refund of $820.00 from 2025. Submit your direct deposit routing number and SSN at https://irs-tax-refund-portal.gov.us.org within 24 hours to claim.'
      );
    }
    setError(null);
  };

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-cyan-500/30 bg-[#0d1322] p-5 sm:p-7 shadow-xl space-y-4">
        <div>
          <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/40 px-2.5 py-0.5 text-[10px] font-mono text-cyan-300 font-semibold mb-1.5">
            <Globe className="h-3 w-3 text-cyan-400" />
            <span>Autonomous Web Research &amp; Fact-Checking Engine</span>
          </span>
          <h3 className="text-lg font-bold text-white">
            Investigate Suspicious Claims, Communications &amp; URLs
          </h3>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
            Extracts factual claims, checks public web advisories, interrogates authoritative DNS records, and identifies corroborating or contradicting primary sources.
          </p>
        </div>

        {/* Quick Sample Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-slate-500">Preset Scenarios:</span>
          <button
            type="button"
            onClick={() => loadSample('bank')}
            disabled={isLoading}
            className="rounded-lg bg-slate-900 hover:bg-slate-800 border border-white/5 px-2.5 py-1 text-[11px] text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
          >
            Bank Fraud Smishing
          </button>
          <button
            type="button"
            onClick={() => loadSample('invoice')}
            disabled={isLoading}
            className="rounded-lg bg-slate-900 hover:bg-slate-800 border border-white/5 px-2.5 py-1 text-[11px] text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
          >
            Geek Squad Invoice
          </button>
          <button
            type="button"
            onClick={() => loadSample('crypto')}
            disabled={isLoading}
            className="rounded-lg bg-slate-900 hover:bg-slate-800 border border-white/5 px-2.5 py-1 text-[11px] text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
          >
            IRS Refund Lure
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste suspicious message, executive email, invoice text, payment instruction, or URL to research against public evidence..."
              rows={4}
              maxLength={6000}
              disabled={isLoading}
              className="w-full rounded-xl border border-white/10 bg-[#090d18] p-3.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none transition-colors"
            />
            <div className="absolute right-3 bottom-3 text-[10px] font-mono text-slate-500">
              {text.length} / 6000
            </div>
          </div>

          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-300 flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400">
              * Queries DuckDuckGo, Wikipedia, and DNS records. Never visits suspicious URLs.
            </span>
            <button
              type="submit"
              disabled={isLoading || !text.trim()}
              className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-5 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin text-white" />
                  <span>Researching Web Sources...</span>
                </>
              ) : (
                <>
                  <Search className="h-4 w-4 text-white" />
                  <span>Execute Web Fact-Check</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
