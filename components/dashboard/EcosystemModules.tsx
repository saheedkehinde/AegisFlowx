'use client';

import React from 'react';
import Link from 'next/link';
import {
  GraduationCap,
  Binary,
  SearchCode,
  Sliders,
  Users,
  Bell,
  Cpu,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';

interface EcosystemModulesProps {
  verifiedAcademyCount: number;
}

export default function EcosystemModules({ verifiedAcademyCount }: EcosystemModulesProps) {
  const modules = [
    {
      title: 'Security Academy',
      badge: verifiedAcademyCount > 0 ? `${verifiedAcademyCount}/4 Verified` : '4 Modules',
      badgeClass: 'text-[var(--accent-violet)] border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)]',
      description:
        'Practice identifying bank smishing, business email compromise, package lures, and crypto extortion across 12 scenario-based quizzes.',
      href: '/academy',
      icon: GraduationCap,
      iconColor: 'text-[var(--accent-violet)]',
      iconBg: 'bg-[var(--accent-violet-subtle)]',
      actionText: 'Enter Academy',
      actionColor: 'text-[var(--accent-violet)]',
      hoverBorder: 'hover:border-[var(--accent-violet)]/50',
      status: 'Interactive Labs',
    },
    {
      title: 'MITRE ATT&CK Matrix',
      badge: 'Taxonomy',
      badgeClass: 'text-[var(--accent-amber)] border-[var(--accent-amber)]/30 bg-[var(--accent-amber-subtle)]',
      description:
        'Explore structured attack matrices covering Spearphishing Link (T1566.002), Voice Phishing (T1566.004), and Internal Impersonation.',
      href: '/threat-intel',
      icon: Binary,
      iconColor: 'text-[var(--accent-amber)]',
      iconBg: 'bg-[var(--accent-amber-subtle)]',
      actionText: 'Explore ATT&CK Matrix',
      actionColor: 'text-[var(--accent-amber)]',
      hoverBorder: 'hover:border-[var(--accent-amber)]/50',
      status: 'Reference',
    },
    {
      title: 'Cryptographic Case Vault',
      badge: 'RLS Protected',
      badgeClass: 'text-[var(--primary-orange)] border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)]',
      description:
        'User-isolated case files with Indicator of Compromise (IOC) timelines, evidentiary defense chains, and forensic dossier exports.',
      href: '/investigations',
      icon: SearchCode,
      iconColor: 'text-[var(--primary-orange)]',
      iconBg: 'bg-[var(--surface-soft-orange)]',
      actionText: 'Open Vault Explorer',
      actionColor: 'text-[var(--primary-orange)]',
      hoverBorder: 'hover:border-[var(--primary-orange)]/50',
      status: 'Cloud & RAM',
    },
  ];

  const secondaryModules = [
    {
      title: 'System Diagnostics & Telemetry',
      badge: 'Diagnostic Engine',
      description: 'Model inference health, Featherless API latency, and SSRF filter status checks.',
      href: '/settings',
      icon: Sliders,
      actionText: 'Inspect Settings',
    },
    {
      title: 'Community Threat Feed',
      badge: 'Preview Mode',
      description: 'Crowdsourced anonymized threat indicators and threat actor telemetry sharing.',
      href: '/community',
      icon: Users,
      actionText: 'Preview Community',
      isPreview: true,
    },
    {
      title: 'Automation & Webhook Center',
      badge: 'Preview Mode',
      description: 'Automated Slack, Discord, and webhook dispatch rules for high-severity alerts.',
      href: '/automation',
      icon: Cpu,
      actionText: 'Preview Automation',
      isPreview: true,
    },
  ];

  return (
    <section aria-label="Learning and Intelligence Ecosystem" className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 border-b border-[var(--border-subtle)] pb-2.5">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-[var(--foreground)] flex items-center gap-2">
            <GraduationCap className="h-4 w-4 text-[var(--accent-violet)]" />
            <span>Threat Literacy &amp; Intelligence Ecosystem</span>
          </h2>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Educational defense playbooks, structured cyber threat frameworks, and security references.
          </p>
        </div>
        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
          Curated Platform Ecosystem
        </span>
      </div>

      {/* Primary 3 Modules */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {modules.map((mod) => {
          const Icon = mod.icon;
          return (
            <Link
              key={mod.title}
              href={mod.href}
              className={`group rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] ${mod.hoverBorder} hover:bg-[var(--surface-interactive)] p-5 transition-all flex flex-col justify-between shadow-sm cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none`}
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div
                    className={`h-9 w-9 rounded-xl ${mod.iconBg} ${mod.iconColor} flex items-center justify-center group-hover:scale-105 transition-transform`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <span
                    className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${mod.badgeClass}`}
                  >
                    {mod.badge}
                  </span>
                </div>

                <div>
                  <h3
                    className={`text-sm font-bold text-[var(--foreground)] group-hover:${mod.actionColor} transition-colors`}
                  >
                    {mod.title}
                  </h3>
                  <p className="mt-1 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    {mod.description}
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <span
                  className={`text-xs font-semibold ${mod.actionColor} flex items-center gap-1 group-hover:translate-x-0.5 transition-transform`}
                >
                  <span>{mod.actionText}</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)]">
                  {mod.status}
                </span>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Secondary 3 Modules (Settings & Preview Capabilities) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
        {secondaryModules.map((mod) => {
          const Icon = mod.icon;
          return (
            <Link
              key={mod.title}
              href={mod.href}
              className="group rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] p-4 transition-all flex items-center justify-between gap-3 shadow-xs"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="h-8 w-8 rounded-lg bg-[var(--surface-interactive)] border border-[var(--border)] text-[var(--muted-foreground)] flex items-center justify-center group-hover:text-[var(--primary-orange)] transition-colors shrink-0">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors truncate">
                      {mod.title}
                    </span>
                    {mod.isPreview && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded border border-[var(--border)] bg-[var(--background)] text-[var(--muted-foreground)]">
                        Preview
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--muted-foreground)] truncate">
                    {mod.description}
                  </p>
                </div>
              </div>

              <ChevronRight className="h-4 w-4 text-[var(--muted-foreground)] group-hover:translate-x-0.5 transition-transform shrink-0" />
            </Link>
          );
        })}
      </div>
    </section>
  );
}
