'use client';

import React from 'react';
import AppShell from '@/components/AppShell';
import {
  Binary,
  ShieldAlert,
  ExternalLink,
  Tag,
  AlertTriangle,
  Link2,
  FileCode,
  Shield,
  Layers,
} from 'lucide-react';
import Link from 'next/link';

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
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400 mb-2">
            <span>Knowledge Base &middot; MITRE ATT&CK Alignment</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <Binary className="h-7 w-7 text-cyan-400" />
            <span>Threat Intelligence &amp; Taxonomies</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Correlated threat actor Tactics, Techniques, and Procedures (TTPs) mapped to real-world social engineering attack vectors.
          </p>
        </div>

        {/* MITRE ATT&CK Matrix Cards */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Social Engineering &amp; Phishing TTPs (MITRE ATT&CK)
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Industry Standard Framework</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {mitreTactics.map((item) => (
              <div
                key={item.id}
                className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-5 space-y-3 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                      {item.id}
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      {item.tactic}
                    </span>
                  </div>

                  <h4 className="mt-2 text-base font-bold text-white">
                    {item.technique}
                  </h4>
                  <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                    {item.description}
                  </p>
                </div>

                <div className="pt-3 border-t border-white/5 space-y-2">
                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                      Key Signatures:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {item.indicators.map((ind, i) => (
                        <span
                          key={i}
                          className="text-[10px] font-mono text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-white/5"
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-cyan-400 block">
                      Defensive Strategy:
                    </span>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {item.defense}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Threat Feeds Architecture Note */}
        <div className="rounded-xl border border-white/10 bg-[#0d1322]/40 p-5 text-xs text-slate-400 leading-relaxed flex items-start gap-3">
          <Shield className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <strong className="text-white">Threat Feed Ingestion Roadmap: </strong>
            Direct API connectors for AbuseIPDB, URLHaus, and OpenCTI STIX feeds are slated for integration in Phase 2. All current threat indicator evaluations are performed live through our Qwen model and heuristic rules.
          </div>
        </div>
      </div>
    </AppShell>
  );
}
