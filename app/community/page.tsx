'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import PageHeader from '@/components/ui/PageHeader';
import { Users, Send, CheckCircle2, Info, Database } from 'lucide-react';

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
        <PageHeader
          breadcrumbLabel="Community"
          title="Community Threat Reports"
          description="Crowdsourced scam trends, smishing wave alerts, and anonymized incident submissions to warn others."
          icon={Users}
          badgeText="Preview Mode"
          badgeVariant="warning"
        />

        {/* Feature Preview & Demonstration Notice */}
        <div className="rounded-2xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-4 sm:p-5 text-[var(--foreground)]">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-[var(--status-warning)] shrink-0 mt-0.5" aria-hidden="true" />
            <div className="space-y-1 text-xs">
              <strong className="text-sm font-bold text-[var(--status-warning)] block">
                Feature Preview: Community Intelligence Network
              </strong>
              <p className="text-[var(--foreground)] leading-relaxed">
                <strong>Roadmap Objective:</strong> AegisFlow will aggregate anonymized threat telemetry, reputation upvoting, and deduplicated scam waves across organizations into a public safety feed.
              </p>
              <p className="text-[var(--foreground-secondary)] leading-relaxed">
                <strong className="text-[var(--foreground)]">Current Status:</strong> Interactive UI Preview. Submissions on this screen are validated and held in temporary local session state for demonstration. They do not publish to live feeds or alter external accounts.
              </p>
            </div>
          </div>
        </div>

        {/* Report Submission Form */}
        <section className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 shadow-[var(--shadow-sm)]">
          <div className="max-w-2xl">
            <h2 className="text-lg font-bold text-[var(--foreground)] flex items-center gap-2 font-[family-name:var(--font-display)]">
              <Send className="h-4 w-4 text-[var(--primary-orange)]" aria-hidden="true" />
              <span>Submit Anonymized Scam Threat</span>
            </h2>
            <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
              Encountered a novel phishing SMS or impersonation email? Test report input handling in preview mode.
            </p>

            {submitted ? (
              <div
                role="status"
                className="mt-6 rounded-xl border border-[var(--status-success-border)] bg-[var(--status-success-bg)] p-4 text-[var(--status-success)] text-xs sm:text-sm flex items-center gap-3"
              >
                <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden="true" />
                <div>
                  <strong className="font-semibold text-[var(--foreground)]">Report Validated Locally: </strong>
                  Your preview submission was validated in local session state. Community database publishing is slated for a future release.
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                <div>
                  <label htmlFor="report-type" className="block text-xs font-semibold text-[var(--foreground)] mb-1.5">
                    Threat Classification
                  </label>
                  <select
                    id="report-type"
                    value={reportType}
                    onChange={(e) => setReportType(e.target.value)}
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2.5 text-xs text-[var(--foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)]"
                  >
                    <option value="smishing">SMS / Text Message Phishing (Smishing)</option>
                    <option value="email-phishing">Email Credential Phishing</option>
                    <option value="bec">Executive Impersonation (CEO / BEC)</option>
                    <option value="delivery">Package Delivery Scam</option>
                    <option value="crypto">Cryptocurrency Recovery / Investment Fraud</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sender-info" className="block text-xs font-semibold text-[var(--foreground)] mb-1.5">
                    Sender Info / Shortcode <span className="text-[var(--muted-foreground)] font-normal">(Optional)</span>
                  </label>
                  <input
                    id="sender-info"
                    type="text"
                    value={senderInfo}
                    onChange={(e) => setSenderInfo(e.target.value)}
                    placeholder="e.g. +1 (800) 555-0199 or alerts@spoofed-domain.xyz"
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2.5 text-xs text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)]"
                  />
                </div>

                <div>
                  <label htmlFor="report-details" className="block text-xs font-semibold text-[var(--foreground)] mb-1.5">
                    Message Body / Content (Redact sensitive personal data)
                  </label>
                  <textarea
                    id="report-details"
                    value={reportDetails}
                    onChange={(e) => setReportDetails(e.target.value)}
                    rows={4}
                    required
                    placeholder="Paste the scam message text here..."
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2.5 text-xs text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)] font-mono"
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    className="rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer"
                  >
                    Submit Report Preview
                  </button>
                </div>
              </form>
            )}
          </div>
        </section>

        {/* Future Community Feed Notice */}
        <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--surface-interactive)]/60 p-8 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--accent-cyan)] mb-3">
            <Database className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
            Community Threat Feed — Upcoming Architecture
          </h3>
          <p className="mt-1 text-xs text-[var(--foreground-secondary)] max-w-md mx-auto leading-relaxed">
            Persistent public feeds, reputation voting, and federated threat intelligence sharing will connect when the community database schema is provisioned.
          </p>
        </div>
      </div>
    </AppShell>
  );
}
