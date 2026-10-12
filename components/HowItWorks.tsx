'use client';

import React from 'react';
import {
  FileText,
  ScanEye,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Link2,
  CreditCard,
  UserX,
  ArrowRight,
} from 'lucide-react';

export default function HowItWorks() {
  const steps = [
    {
      step: '01',
      title: 'Paste a message',
      description:
        'Copy any suspicious text from SMS, email, WhatsApp, Slack, or an unexpected direct message. Remove private PII before submitting.',
      icon: FileText,
      tag: 'Input Phase',
    },
    {
      step: '02',
      title: 'Understand the warning signs',
      description:
        'Our threat engine inspects linguistic urgency, domain reputation, coercive psychological patterns, and financial anomalies.',
      icon: ScanEye,
      tag: 'Analysis Phase',
    },
    {
      step: '03',
      title: 'Take safer action',
      description:
        'Follow a prioritized, clear defensive checklist: verify via authorized channels, avoid malware traps, and report the scam.',
      icon: ShieldCheck,
      tag: 'Defense Phase',
    },
  ];

  const threatVectors = [
    {
      icon: Clock,
      title: 'Manufactured Urgency',
      subtitle: 'Time Pressure & Coercion',
      description:
        'Scammers fabricate deadlines ("within 15 minutes", "account freeze") to trigger panic, preventing you from pausing to think or verify with colleagues.',
    },
    {
      icon: UserX,
      title: 'Authority Spoofing',
      subtitle: 'Banks, Postal, Executives',
      description:
        'Attackers impersonate respected entities (Wells Fargo, USPS, your CEO) to exploit conditioned obedience and trust in organizational hierarchy.',
    },
    {
      icon: Link2,
      title: 'Deceptive Hyperlinks',
      subtitle: 'Lookalikes & URL Shorteners',
      description:
        'Links disguised using shorteners (bit.ly) or typo-squatted domains (.top, .xyz) direct users to fake login portals designed to harvest passwords.',
    },
    {
      icon: CreditCard,
      title: 'Untraceable Payment Demands',
      subtitle: 'Gift Cards, Crypto & P2P',
      description:
        'Requests for Apple gift cards, Western Union, Bitcoin, or small redelivery fees are always malicious. Real institutions never require gift card pin codes.',
    },
  ];

  return (
    <section id="how-it-works" className="relative mx-auto max-w-6xl px-4 sm:px-6 lg:px-8 py-20">
      {/* Section Header */}
      <div className="text-center max-w-2xl mx-auto">
        <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
          Workflow
        </h2>
        <h3 className="mt-2 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
          How AegisFlow Works
        </h3>
        <p className="mt-3 text-base text-slate-400">
          A three-step verification loop engineered to stop social engineering attacks in their tracks.
        </p>
      </div>

      {/* 3 Steps */}
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6 relative">
        {steps.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={item.step}
              className="relative rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-7 backdrop-blur-md transition-all hover:border-cyan-500/30 hover:bg-[#11192e]/90 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <span className="font-mono text-2xl font-black text-cyan-500/80">
                    {item.step}
                  </span>
                  <span className="text-[11px] font-semibold tracking-wider uppercase text-slate-400 border border-white/5 bg-white/[0.03] px-2.5 py-0.5 rounded-full">
                    {item.tag}
                  </span>
                </div>
                <div className="h-10 w-10 rounded-xl bg-cyan-600/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4">
                  <Icon className="h-5 w-5" />
                </div>
                <h4 className="text-lg font-bold text-white tracking-tight">
                  {item.title}
                </h4>
                <p className="mt-2 text-sm text-slate-300 leading-relaxed">
                  {item.description}
                </p>
              </div>

              {idx < steps.length - 1 && (
                <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-slate-600">
                  <ArrowRight className="h-5 w-5" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Threat Vectors Educational Section */}
      <div id="threat-vectors" className="mt-20">
        <div className="text-center max-w-2xl mx-auto mb-10">
          <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            Threat Intelligence
          </h2>
          <h3 className="mt-2 text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
            Common Social Engineering Red Flags
          </h3>
          <p className="mt-2 text-sm text-slate-400">
            Understand how modern cybercriminals exploit cognitive vulnerabilities.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {threatVectors.map((v) => {
            const Icon = v.icon;
            return (
              <div
                key={v.title}
                className="rounded-xl border border-white/5 bg-slate-900/40 p-5 hover:border-cyan-500/20 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="h-9 w-9 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-3">
                    <Icon className="h-4.5 w-4.5" />
                  </div>
                  <h4 className="text-sm font-bold text-white">
                    {v.title}
                  </h4>
                  <p className="text-[11px] font-medium text-cyan-400/90 mb-2">
                    {v.subtitle}
                  </p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {v.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
