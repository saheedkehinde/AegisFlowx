'use client';

import React from 'react';
import AppShell from '@/components/AppShell';
import PageHeader from '@/components/ui/PageHeader';
import { Binary, Shield } from 'lucide-react';

export default function ThreatIntelPage() {
  const mitreTactics = [
    {
      id: 'T1566.001',
      technique: 'Phishing: Spearphishing Link',
      tactic: 'Initial Access',
      description:
        'Adversaries send spearphishing messages with a malicious link designed to lure the target to a credential-harvesting web portal.',
      indicators: ['Shortened URLs (bit.ly)', 'Typosquatted TLDs (.top, .xyz)', 'Homograph domain spoofing'],
      defense: 'Automated URL defanging, strict SPF/DKIM validation, out-of-band confirmation.',
    },
    {
      id: 'T1566.002',
      technique: 'Phishing: Spearphishing Attachment',
      tactic: 'Initial Access',
      description:
        'Attackers send messages containing malicious files disguised as invoices, receipts, or administrative spreadsheets.',
      indicators: ['Macro-enabled documents (.docm)', 'Encrypted zip files with password in body', 'Double extension files'],
      defense: 'Zero-trust attachment sandboxing, binary inspection, disallowing macros.',
    },
    {
      id: 'T1598',
      technique: 'Phishing for Information',
      tactic: 'Reconnaissance',
      description:
        'Targeted communications seeking internal network topologies, org charts, or verification codes without direct payload delivery.',
      indicators: ['Posing as IT Helpdesk / Executive assistant', 'Requests for OTPs or SMS confirmation tokens'],
      defense: 'Strict zero-disclosure policies, mandatory multi-person verification for credentials.',
    },
    {
      id: 'T1534',
      technique: 'Internal Spearphishing (BEC)',
      tactic: 'Lateral Movement',
      description:
        'Adversaries leverage compromised internal accounts or convincing executive impersonation to request urgent wire transfers or gift cards.',
      indicators: ['Executive in urgent meeting claiming unavailable for phone calls', 'Demands for secrecy'],
      defense: 'Out-of-band telephone verification, dual authorization on financial transactions.',
    },
  ];

  return (
    <AppShell>
      <div className="space-y-8">
        <PageHeader
          breadcrumbLabel="Threat Intel"
          title="Threat Intelligence & Taxonomies"
          description="Correlated threat actor Tactics, Techniques, and Procedures (TTPs) mapped to real-world social engineering attack vectors."
          icon={Binary}
          badgeText="MITRE ATT&CK Alignment"
          badgeVariant="cyan"
        />

        {/* MITRE ATT&CK Matrix Cards */}
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)]">
              Social Engineering &amp; Phishing TTPs (MITRE ATT&amp;CK)
            </h2>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
              Industry Standard Framework
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {mitreTactics.map((item) => (
              <article
                key={item.id}
                className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 space-y-4 flex flex-col justify-between shadow-[var(--shadow-sm)] hover:border-[var(--primary-orange)]/40 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] px-2.5 py-0.5 rounded-md border border-[var(--accent-cyan)]/30">
                      {item.id}
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--muted-foreground)]">
                      {item.tactic}
                    </span>
                  </div>

                  <h3 className="mt-3 text-base font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                    {item.technique}
                  </h3>
                  <p className="mt-1.5 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                    {item.description}
                  </p>
                </div>

                <div className="pt-3.5 border-t border-[var(--border-subtle)] space-y-3">
                  <div>
                    <span className="text-[10px] uppercase font-bold tracking-wider text-[var(--muted-foreground)] block mb-1.5">
                      Key Signatures
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {item.indicators.map((ind, i) => (
                        <span
                          key={i}
                          className="text-[11px] font-mono text-[var(--foreground)] bg-[var(--surface-interactive)] px-2 py-0.5 rounded-md border border-[var(--border-subtle)]"
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold tracking-wider text-[var(--primary-orange)] block">
                      Defensive Strategy
                    </span>
                    <p className="text-xs text-[var(--foreground-secondary)] mt-0.5 leading-relaxed">
                      {item.defense}
                    </p>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </section>

        {/* Live Threat Feeds Architecture Note */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-interactive)] p-5 text-xs text-[var(--foreground-secondary)] leading-relaxed flex items-start gap-3">
          <Shield className="h-5 w-5 text-[var(--accent-cyan)] shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <strong className="text-[var(--foreground)]">Threat Feed Ingestion Architecture: </strong>
            Direct threat connectors integrate active global indicator feeds and malware distribution databases. All current threat evaluations are performed live through Aegis AI and automated behavioral rules.
          </div>
        </div>
      </div>
    </AppShell>
  );
}
