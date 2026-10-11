'use client';

import React from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import {
  SearchCode,
  ShieldAlert,
  ArrowRight,
  Database,
  Lock,
  GitBranch,
  FolderGit2,
  FileCheck,
} from 'lucide-react';

export default function InvestigationsPage() {
  const plannedPillars = [
    {
      title: 'Digital Chain of Custody',
      description:
        'Cryptographically hash original message submissions and raw model outputs for forensic compliance and audit trails.',
      icon: Lock,
    },
    {
      title: 'IOC Cross-Correlation',
      description:
        'Correlate URLs, IP addresses, sending domains, and phone numbers across multiple flagged incidents.',
      icon: GitBranch,
    },
    {
      title: 'Incident Dossier Export',
      description:
        'Export standardized STIX/TAXII JSON bundles and executive incident briefs for corporate incident response teams.',
      icon: FileCheck,
    },
  ];

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Module Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2.5 py-0.5 text-[10px] font-mono text-slate-400 mb-2">
            <span>Planned Module &middot; Phase 2</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <SearchCode className="h-7 w-7 text-cyan-400" />
            <span>Threat Investigations</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Case management, forensic correlation, and structured timeline analysis for elevated security events.
          </p>
        </div>

        {/* Real Architectural State Notice */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-6">
            <div className="max-w-xl">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-bold">
                <Database className="h-4 w-4" />
                <span>Case Database Architecture (Phase 2 Roadmap)</span>
              </div>
              <h3 className="mt-2 text-lg font-bold text-white">
                Zero-Retention Mode Currently Active
              </h3>
              <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
                AegisFlow currently runs in strict zero-retention mode: analyses are conducted entirely in volatile memory and discarded when closed. Persistent multi-user case investigations, tagging, and team collaboration will be enabled with the Phase 2 database rollout.
              </p>
              <div className="mt-5">
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-white transition-colors"
                >
                  <ShieldAlert className="h-4 w-4" />
                  <span>Perform Live Single-Message Analysis</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>

            <div className="rounded-xl border border-white/5 bg-slate-900/60 p-4 text-xs font-mono text-slate-400 sm:w-72">
              <span className="text-slate-300 font-bold block mb-2">Case Data Model (Preview):</span>
              <ul className="space-y-1.5 text-[11px] text-slate-400">
                <li>&middot; case_id: UUIDv7</li>
                <li>&middot; status: TRIAGE | ACTIVE | CLOSED</li>
                <li>&middot; threat_vector: SOCIAL_ENGINEERING</li>
                <li>&middot; iocs_extracted: Array&lt;IOC&gt;</li>
                <li>&middot; evidence_hash: SHA-256</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Planned Capabilities */}
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-4">
            Investigation Architecture Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {plannedPillars.map((pillar) => {
              const Icon = pillar.icon;
              return (
                <div
                  key={pillar.title}
                  className="rounded-xl border border-white/5 bg-[#0d1322]/50 p-5"
                >
                  <div className="h-9 w-9 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center mb-3">
                    <Icon className="h-4.5 w-4.5" />
                  </div>
                  <h4 className="text-sm font-bold text-white">{pillar.title}</h4>
                  <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
                    {pillar.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
