'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import {
  GraduationCap,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  ArrowRight,
  BookOpen,
  FileQuestion,
  HelpCircle,
} from 'lucide-react';

export default function AcademyPage() {
  const [activeLesson, setActiveLesson] = useState<number>(0);

  const lessons = [
    {
      id: 1,
      title: 'Anatomy of Urgent Bank Fraud Smishing',
      category: 'Financial Phishing',
      level: 'Beginner',
      readTime: '4 min',
      summary:
        'How cybercriminals fabricate unauthorized charges to instill panic and push victims to shortened verification domains.',
      redFlags: [
        'Unusually specific or large fake debit dollar amounts ($1,429.99)',
        'Arbitrary, strict deadlines ("within 15 minutes", "avoid account freeze")',
        'Shortened hyperlinks (bit.ly, tinyurl) masquerading as official portals',
        'Requests to reply "NO" to confirm active phone recipient numbers',
      ],
      defenses: [
        'Never click links sent via unsolicited SMS, even if sender ID says your bank.',
        'Always open the authentic banking app directly from your home screen.',
        'Call the official phone number printed on the back of your physical card.',
      ],
      exampleSnippet:
        "WELLS FARGO ALERT: Suspicious debit of $1,429.99 flagged. Reply NO or click https://bit.ly/wf-sec to avoid account freeze within 15 mins.",
    },
    {
      id: 2,
      title: 'Business Email Compromise (BEC) & Executive Fraud',
      category: 'Corporate Social Engineering',
      level: 'Intermediate',
      readTime: '5 min',
      summary:
        'Attackers impersonating C-level leadership requesting secretive gift card purchases or confidential wire transfers.',
      redFlags: [
        'Sender claims to be stuck in an all-day executive board meeting unable to talk',
        'Strict emphasis on secrecy ("keep this quiet", "strictly confidential")',
        'Requests for untraceable payment media: Apple, Steam, or Vanilla Visa gift cards',
        'Urgent instructions to scratch off PIN codes and send photos immediately',
      ],
      defenses: [
        'No legitimate executive will ever instruct an employee to purchase gift cards for business operations.',
        'Always verify through an out-of-band channel (call internal phone extension or ask in person).',
        'Report the spoofed email header to internal security/IT helpdesk.',
      ],
      exampleSnippet:
        "Hi, I'm currently stuck in an all-day confidential executive board review and can't take phone calls. I urgently need you to purchase 5x $100 Apple Gift Cards before 3 PM. Scratch the back and email photos of the PIN codes. Keep this quiet.",
    },
    {
      id: 3,
      title: 'Package Delivery Smishing & Advance Fee Schemes',
      category: 'Postal Impersonation',
      level: 'Beginner',
      readTime: '3 min',
      summary:
        'Fake USPS, UPS, or FedEx delivery alerts requesting nominal insurance or redelivery fees to steal credit card details.',
      redFlags: [
        'Claims that delivery address was incomplete or missing street numbers',
        'Request for an unusual nominal fee ($1.85 or $2.10) to cover "reshipment"',
        'Lookalike non-standard domains (usps-track-resolve.top or fedex-delivery.xyz)',
        'Threat of returning package to sender within 24 hours',
      ],
      defenses: [
        'Postal services never require credit card payments via SMS links to deliver mail.',
        'Track parcels directly on the official USPS.com or carrier website using the tracking number.',
        'Forward smishing SMS messages to 7726 (SPAM).',
      ],
      exampleSnippet:
        "USPS Tracking: Package shipment #US940012847 cannot be delivered due to incomplete street address numbers. Please update your delivery details and pay the mandatory $1.85 redelivery insurance fee at https://usps-track-resolve.top/deliver within 24 hours.",
    },
    {
      id: 4,
      title: 'Cryptocurrency Recovery & Tech Support Extortion',
      category: 'Advanced Social Engineering',
      level: 'Advanced',
      readTime: '6 min',
      summary:
        'Attackers posing as blockchain investigators or cybersecurity specialists promising to recover lost funds for an upfront fee.',
      redFlags: [
        'Guaranteed recovery of lost crypto assets or stolen wallet funds',
        'Demands for remote desktop access (AnyDesk, TeamViewer)',
        'Upfront "gas fees", "legal escrow", or blockchain verification deposits',
        'Unsolicited DMs on Telegram, Reddit, or Discord offering recovery services',
      ],
      defenses: [
        'Blockchain transactions are mathematically irreversible; anyone promising guaranteed private key recovery is a scammer.',
        'Never install remote desktop software for unverified third parties.',
        'Never disclose 12/24-word seed recovery phrases to anyone.',
      ],
      exampleSnippet:
        "Blockchain Forensic Bureau: We have located your stolen $12,400 USDT. Please connect your wallet to our recovery escrow portal and pay 0.05 ETH gas fee to release funds.",
    },
  ];

  const current = lessons[activeLesson];

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400 mb-2">
            <span>Educational Guides &middot; Threat Literacy</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <GraduationCap className="h-7 w-7 text-cyan-400" />
            <span>AegisFlow Security Academy</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Interactive digital safety playbooks designed to deconstruct deceptive psychological engineering tactics before harm occurs.
          </p>
        </div>

        {/* Lesson Selector Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {lessons.map((lesson, idx) => (
            <button
              key={lesson.id}
              type="button"
              onClick={() => setActiveLesson(idx)}
              className={`text-left rounded-xl border p-4 transition-all cursor-pointer ${
                activeLesson === idx
                  ? 'border-cyan-500 bg-[#10192e] ring-1 ring-cyan-500/50'
                  : 'border-white/10 bg-[#0d1322]/80 hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-mono mb-2">
                <span className="text-cyan-400 font-bold">Module {lesson.id}</span>
                <span className="text-slate-500">{lesson.readTime}</span>
              </div>
              <h3 className="text-xs font-bold text-white line-clamp-2">
                {lesson.title}
              </h3>
              <div className="mt-2 text-[10px] font-mono text-slate-400">
                {lesson.level}
              </div>
            </button>
          ))}
        </div>

        {/* Selected Lesson Reader */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/90 p-6 sm:p-8 space-y-6">
          <div className="border-b border-white/5 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
              <span>{current.category}</span>
              <span>&middot;</span>
              <span>{current.level}</span>
            </div>
            <h3 className="text-xl sm:text-2xl font-bold text-white">
              {current.title}
            </h3>
            <p className="mt-2 text-sm text-slate-300 leading-relaxed">
              {current.summary}
            </p>
          </div>

          {/* Red Flags & Defenses */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="rounded-xl border border-red-500/20 bg-red-950/15 p-5">
              <h4 className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-2 mb-3">
                <AlertOctagon className="h-4 w-4" />
                <span>Primary Attack Red Flags</span>
              </h4>
              <ul className="space-y-2 text-xs text-slate-300">
                {current.redFlags.map((flag, i) => (
                  <li key={i} className="flex items-start gap-2 leading-relaxed">
                    <span className="text-red-400 font-bold">&times;</span>
                    <span>{flag}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/15 p-5">
              <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2 mb-3">
                <CheckCircle2 className="h-4 w-4" />
                <span>Recommended Defense Protocol</span>
              </h4>
              <ul className="space-y-2 text-xs text-slate-300">
                {current.defenses.map((def, i) => (
                  <li key={i} className="flex items-start gap-2 leading-relaxed">
                    <span className="text-emerald-400 font-bold">&check;</span>
                    <span>{def}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Practical Live Test CTA */}
          <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <span className="text-xs font-bold text-cyan-300 block">
                Practice Live Detection with AegisFlow
              </span>
              <p className="text-xs text-slate-400 mt-0.5">
                Test this scenario in the AI Message Analyzer to see exact model indicators.
              </p>
            </div>

            <Link
              href="/analyze"
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-xs font-semibold text-white transition-colors shrink-0"
            >
              <span>Test Scenario in Analyzer</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
