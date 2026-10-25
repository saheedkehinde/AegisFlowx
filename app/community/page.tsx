'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import {
  Users,
  Send,
  ShieldCheck,
  CheckCircle2,
  Info,
  Database,
  Lock,
} from 'lucide-react';

export default function CommunityPage() {
  const [reportType, setReportType] = useState('smishing');
  const [reportDetails, setReportDetails] = useState('');
  const [senderInfo, setSenderInfo] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportDetails.trim()) return;
    setSubmitted(true);
    setTimeout(() => {
      setSubmitted(false);
      setReportDetails('');
      setSenderInfo('');
    }, 4000);
  };

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400">
              Community Defense &middot; Crowdsourced Intelligence
            </span>
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-950/40 px-2 py-0.5 text-[10px] font-mono font-semibold text-amber-300">
              Preview Mode
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <Users className="h-7 w-7 text-cyan-400" />
            <span>Community Threat Reports</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Crowdsourced scam trends, smishing wave alerts, and anonymized incident submissions to warn others.
          </p>
        </div>

        {/* Feature Preview & Demonstration Notice */}
        <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 sm:p-5 text-slate-200">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1 text-xs">
              <strong className="text-sm font-bold text-amber-200 block">
                Feature Preview: Community Intelligence Network
              </strong>
              <p className="text-slate-300 leading-relaxed">
                <strong className="text-white">Roadmap Objective:</strong> AegisFlow will aggregate anonymized threat telemetry, reputation upvoting, and deduplicated scam waves across organizations into a public safety feed.
              </p>
              <p className="text-slate-400 leading-relaxed">
                <strong className="text-slate-300">Current Status:</strong> Interactive UI Preview. Submissions on this screen are validated and stored in temporary local session state for demonstration. They do not publish to live feeds or alter external accounts.
              </p>
            </div>
          </div>
        </div>

        {/* Report Submission Form */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-8">
          <div className="max-w-2xl">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Send className="h-4 w-4 text-cyan-400" />
              <span>Submit Anonymized Scam Threat</span>
            </h3>
            <p className="mt-1 text-xs text-slate-400 leading-relaxed">
              Encountered a novel phishing SMS or impersonation email? Test report input handling in preview mode.
            </p>

            {submitted ? (
              <div className="mt-6 rounded-xl border border-emerald-500/30 bg-emerald-950/30 p-4 text-emerald-300 text-xs sm:text-sm flex items-center gap-3">
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                <div>
                  <strong className="font-semibold text-white">Report Cached Locally: </strong>
                  Thank you! Your submission was validated and queued in local session state. Community database publishing will activate in Phase 2.
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                <div>
                  <label htmlFor="report-type" className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Threat Classification
                  </label>
                  <select
                    id="report-type"
                    value={reportType}
                    onChange={(e) => setReportType(e.target.value)}
                    className="w-full rounded-xl border border-white/10 bg-[#090d18] px-3.5 py-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="smishing">SMS / Text Message Phishing (Smishing)</option>
                    <option value="email-phishing">Email Credential Phishing</option>
                    <option value="bec">Executive Impersonation (CEO / BEC)</option>
                    <option value="delivery">Package Delivery Scam</option>
                    <option value="crypto">Cryptocurrency Recovery / Investment Fraud</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sender-info" className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Sender Info / Shortcode (Optional)
                  </label>
                  <input
                    id="sender-info"
                    type="text"
                    value={senderInfo}
                    onChange={(e) => setSenderInfo(e.target.value)}
                    placeholder="e.g. +1 (800) 555-0199 or alerts@spoofed-domain.xyz"
                    className="w-full rounded-xl border border-white/10 bg-[#090d18] px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label htmlFor="report-details" className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Message Body / Content (Redact sensitive personal data)
                  </label>
                  <textarea
                    id="report-details"
                    value={reportDetails}
                    onChange={(e) => setReportDetails(e.target.value)}
                    rows={4}
                    required
                    placeholder="Paste the scam message text here..."
                    className="w-full rounded-xl border border-white/10 bg-[#090d18] px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none font-mono"
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    className="rounded-xl bg-cyan-600 hover:bg-cyan-500 px-5 py-2.5 text-xs font-semibold text-white shadow-md transition-colors cursor-pointer"
                  >
                    Submit Report Preview
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>

        {/* Phase 2 Database Feed Notice */}
        <div className="rounded-2xl border border-white/5 bg-[#0d1322]/40 p-8 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 border border-white/10 text-slate-400 mb-3">
            <Database className="h-6 w-6" />
          </div>
          <h4 className="text-sm font-bold text-white">
            Community Threat Feed — Phase 2 Architecture
          </h4>
          <p className="mt-1 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            Persistent public feeds, reputation voting, and federated threat intelligence sharing will connect when the community database is provisioned in the next phase.
          </p>
        </div>
      </div>
    </AppShell>
  );
}
