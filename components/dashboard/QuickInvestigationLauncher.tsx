'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  Link2,
  UploadCloud,
  Globe,
  ArrowRight,
  Layers,
  Sparkles,
} from 'lucide-react';

export default function QuickInvestigationLauncher() {
  const vectors = [
    {
      title: 'Suspicious Message Analyzer',
      tag: 'Direct Inference',
      tagColor: 'text-[var(--primary-orange)]',
      tagBg: 'bg-[var(--surface-soft-orange)] border-[var(--primary-orange)]/30',
      description:
        'Evaluate urgent smishing SMS, CEO gift-card BEC schemes, and coercive banking alerts with automated IOC defanging.',
      href: '/analyze',
      icon: ShieldAlert,
      iconColor: 'text-[var(--primary-orange)]',
      iconBg: 'bg-[var(--surface-soft-orange)]',
      badge: 'Qwen3-VL-8B',
      bullets: [
        'Automated URL, email & phone defanging',
        'Behavioral OTP interception heuristics',
        'Evidence-calibrated confidence score',
      ],
      actionText: 'Launch Message Analyzer',
      actionColor: 'text-[var(--primary-orange)]',
      hoverBorder: 'hover:border-[var(--primary-orange)]/50',
    },
    {
      title: 'URL Intelligence Workspace',
      tag: 'Dedicated Intel',
      tagColor: 'text-[var(--primary-orange)]',
      tagBg: 'bg-[var(--surface-soft-orange)] border-[var(--primary-orange)]/30',
      description:
        'Investigate suspicious links with authoritative SSRF screening, URLhaus abuse telemetry, DNS lookups, and web evidence.',
      href: '/url-investigation',
      icon: Link2,
      iconColor: 'text-[var(--primary-orange)]',
      iconBg: 'bg-[var(--surface-soft-orange)]',
      badge: 'URLhaus · DNS',
      bullets: [
        'Authoritative SSRF & cloud metadata blocks',
        'Real-time abuse.ch URLhaus query',
        'DNS A/AAAA/NS/MX resolution telemetry',
      ],
      actionText: 'Launch URL Intel',
      actionColor: 'text-[var(--primary-orange)]',
      hoverBorder: 'hover:border-[var(--primary-orange)]/50',
    },
    {
      title: 'Document & Screenshot Scanner',
      tag: 'Multimodal Vision',
      tagColor: 'text-[var(--accent-cyan)]',
      tagBg: 'bg-[var(--accent-cyan-subtle)] border-[var(--accent-cyan)]/30',
      description:
        'Upload PDF invoices, account suspension letters, or chat screenshots for visual OCR extraction and prompt-injection defense.',
      href: '/analyze?tab=document',
      icon: UploadCloud,
      iconColor: 'text-[var(--accent-cyan)]',
      iconBg: 'bg-[var(--accent-cyan-subtle)]',
      badge: 'Vision OCR',
      bullets: [
        'PDF magic-byte validation & layout parse',
        'Prompt-injection containment defenses',
        'Fact vs. inference threat boundary',
      ],
      actionText: 'Launch Document Scanner',
      actionColor: 'text-[var(--accent-cyan)]',
      hoverBorder: 'hover:border-[var(--accent-cyan)]/50',
    },
    {
      title: 'Web-Research Fact-Checker',
      tag: 'URLhaus Grounded',
      tagColor: 'text-[var(--accent-violet)]',
      tagBg: 'bg-[var(--accent-violet-subtle)] border-[var(--accent-violet)]/30',
      description:
        'Cross-examine deceptive claims and suspicious domains against live authenticated web sources and malware threat databases.',
      href: '/analyze?tab=factcheck',
      icon: Globe,
      iconColor: 'text-[var(--accent-violet)]',
      iconBg: 'bg-[var(--accent-violet-subtle)]',
      badge: 'Serper · URLhaus',
      bullets: [
        'Pre-search claim assessability screening',
        'SSRF & loopback protected threat checks',
        'Multi-source citation grounding',
      ],
      actionText: 'Launch Claim Fact-Checker',
      actionColor: 'text-[var(--accent-violet)]',
      hoverBorder: 'hover:border-[var(--accent-violet)]/50',
    },
  ];

  return (
    <section aria-label="Primary Investigation Vectors" className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
            <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Primary Investigation Vectors</span>
          </h2>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Specialized multimodal analyzers calibrated against social engineering heuristics.
          </p>
        </div>
        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
          Select an investigation vector
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {vectors.map((vec) => {
          const Icon = vec.icon;
          return (
            <Link
              key={vec.title}
              href={vec.href}
              className={`group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] ${vec.hoverBorder} hover:bg-[var(--surface-interactive)] p-5 sm:p-6 transition-all duration-200 flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none`}
            >
              <div className="space-y-3.5">
                <div className="flex items-center justify-between">
                  <div
                    className={`h-10 w-10 rounded-xl ${vec.iconBg} ${vec.iconColor} flex items-center justify-center group-hover:scale-105 transition-transform`}
                  >
                    <Icon className="h-5 w-5" />
                  </div>
                  <span
                    className={`text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${vec.tagBg} ${vec.tagColor}`}
                  >
                    {vec.tag}
                  </span>
                </div>

                <div>
                  <h3 className={`text-base font-bold text-[var(--foreground)] group-hover:${vec.actionColor} transition-colors`}>
                    {vec.title}
                  </h3>
                  <p className="mt-1.5 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    {vec.description}
                  </p>
                </div>

                <ul className="space-y-1.5 text-[11px] text-[var(--muted-foreground)] pt-3 border-t border-[var(--border-subtle)]">
                  {vec.bullets.map((bullet, idx) => (
                    <li key={idx} className="flex items-center gap-2">
                      <span className="h-1 w-1 rounded-full bg-[var(--primary-orange)] shrink-0" />
                      <span className="truncate">{bullet}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mt-5 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span
                  className={`text-xs font-semibold ${vec.actionColor} group-hover:translate-x-0.5 transition-transform flex items-center gap-1.5`}
                >
                  <span>{vec.actionText}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                  {vec.badge}
                </span>
              </div>
            </Link>
          );
        })}
      </div>
    </section>
  );
}
