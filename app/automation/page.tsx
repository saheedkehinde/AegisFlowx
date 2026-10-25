'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import {
  Cpu,
  Zap,
  ArrowRight,
  ShieldAlert,
  Webhook,
  Mail,
  FileJson,
  CheckCircle2,
  Lock,
} from 'lucide-react';

export default function AutomationPage() {
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);

  const playbooks = [
    {
      id: 'pb-1',
      name: 'High-Risk Smishing Triage & Webhook Alert',
      trigger: 'On High Risk Assessment (Score >= 80)',
      steps: [
        'Extract defanged URLs and telephone indicators',
        'Package structured JSON payload',
        'Dispatch secure webhook to SecOps Slack / Teams channel',
      ],
      icon: Webhook,
      tag: 'Notification Playbook',
    },
    {
      id: 'pb-2',
      name: 'Executive BEC Fraud Containment Protocol',
      trigger: 'On Impersonation / Gift Card Vector Match',
      steps: [
        'Flag email headers and identify purported executive name',
        'Auto-generate out-of-band verification guidance for recipient',
        'Notify internal finance / payroll administrators',
      ],
      icon: Mail,
      tag: 'Finance Protection',
    },
    {
      id: 'pb-3',
      name: 'Automated IOC Export to SIEM',
      trigger: 'On Verified Threat Extraction',
      steps: [
        'Normalize extracted IOCs into STIX 2.1 JSON bundle',
        'Defang domains (hxxp, [.]) to prevent accidental clicks',
        'Generate download link or forward to syslog endpoint',
      ],
      icon: FileJson,
      tag: 'SIEM Integration',
    },
  ];

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400">
              Workflow Automation &middot; Playbook Blueprints
            </span>
            <span className="inline-flex items-center gap-1 rounded-md border border-indigo-500/30 bg-indigo-950/40 px-2 py-0.5 text-[10px] font-mono font-semibold text-indigo-300">
              Preview Mode
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <Cpu className="h-7 w-7 text-cyan-400" />
            <span>Automation Center</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Orchestrate incident alerts, SIEM exports, and defensive containment actions when threats are confirmed.
          </p>
        </div>

        {/* Feature Preview & Demonstration Notice */}
        <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-4 sm:p-5 text-slate-200">
          <div className="flex items-start gap-3">
            <Zap className="h-5 w-5 text-indigo-400 shrink-0 mt-0.5" />
            <div className="space-y-1 text-xs">
              <strong className="text-sm font-bold text-indigo-200 block">
                Feature Preview: Automated Incident Response (SOAR)
              </strong>
              <p className="text-slate-300 leading-relaxed">
                <strong className="text-white">Roadmap Objective:</strong> Headless webhook execution, automated SIEM STIX 2.1 IOC packaging, and immediate messaging channel alerts (Slack/Teams) on verified critical threats.
              </p>
              <p className="text-slate-400 leading-relaxed">
                <strong className="text-slate-300">Current Status:</strong> Interactive Playbook Catalog Preview. Inspecting or selecting the blueprint playbooks below demonstrates the logic flow and JSON dispatch contract without firing real outbound webhooks or altering production infrastructure.
              </p>
            </div>
          </div>
        </div>

        {/* Playbook Templates */}
        <div className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Automated Playbook Blueprints ({playbooks.length})
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {playbooks.map((pb) => {
              const Icon = pb.icon;
              const isSelected = selectedPlaybook === pb.id;
              return (
                <div
                  key={pb.id}
                  onClick={() => setSelectedPlaybook(isSelected ? null : pb.id)}
                  className={`rounded-2xl border p-5 transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'border-cyan-500 bg-[#10192e] ring-1 ring-cyan-500/50'
                      : 'border-white/10 bg-[#0d1322]/80 hover:border-white/20'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="h-9 w-9 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
                        <Icon className="h-4.5 w-4.5" />
                      </div>
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/20">
                        {pb.tag}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-white">
                      {pb.name}
                    </h4>

                    <div className="mt-2 rounded bg-black/40 px-2.5 py-1 text-[11px] font-mono text-slate-400 border border-white/5">
                      <strong className="text-slate-300">Trigger:</strong> {pb.trigger}
                    </div>

                    <div className="mt-3 space-y-1.5">
                      <span className="text-[10px] uppercase font-bold text-slate-500">
                        Execution Sequence:
                      </span>
                      {pb.steps.map((step, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-1.5 text-xs text-slate-300 leading-snug"
                        >
                          <span className="text-cyan-400 font-mono font-bold text-[10px]">
                            {i + 1}.
                          </span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-xs text-cyan-400 font-medium">
                    <span>{isSelected ? 'Selected Blueprint' : 'Inspect Blueprint'}</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
