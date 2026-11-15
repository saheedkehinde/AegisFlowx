'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import PageHeader from '@/components/ui/PageHeader';
import {
  Cpu,
  Zap,
  ArrowRight,
  Webhook,
  Mail,
  FileJson,
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
      statusLabel: 'Configured Blueprint',
      samplePayload: `{
  "event": "aegisflow.threat.high_risk",
  "mode": "dry_run_preview",
  "severity_score": 88,
  "channel": "secops-triage-webhook",
  "indicators_defanged": ["hxxps://verify-bank-login[.]top"]
}`,
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
      statusLabel: 'Simulated Preview',
      samplePayload: `{
  "event": "aegisflow.bec.impersonation_detected",
  "mode": "dry_run_preview",
  "vector": "executive_wire_request",
  "recommended_action": "out_of_band_voice_verification"
}`,
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
      statusLabel: 'Configured Blueprint',
      samplePayload: `{
  "type": "bundle",
  "spec_version": "2.1",
  "mode": "dry_run_preview",
  "objects": [
    { "type": "indicator", "pattern": "[domain-name:value = 'verify-bank-login.top']" }
  ]
}`,
    },
  ];

  const activeBlueprint = playbooks.find((pb) => pb.id === selectedPlaybook) || null;

  return (
    <AppShell>
      <div className="space-y-8">
        <PageHeader
          breadcrumbLabel="Automation"
          title="Automation Center"
          description="Orchestrate incident alerts, SIEM exports, and defensive containment actions when threats are confirmed."
          icon={Cpu}
          badgeText="Preview Mode"
          badgeVariant="violet"
        />

        {/* Feature Preview & Demonstration Notice */}
        <div className="rounded-2xl border border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] p-4 sm:p-5 text-[var(--foreground)]">
          <div className="flex items-start gap-3">
            <Zap className="h-5 w-5 text-[var(--accent-violet)] shrink-0 mt-0.5" aria-hidden="true" />
            <div className="space-y-1 text-xs">
              <strong className="text-sm font-bold text-[var(--accent-violet)] block">
                Feature Preview: Automated Incident Response (SOAR)
              </strong>
              <p className="text-[var(--foreground)] leading-relaxed">
                <strong>Roadmap Objective:</strong> Headless webhook execution, automated SIEM STIX 2.1 IOC packaging, and immediate messaging channel alerts (Slack/Teams) on verified critical threats.
              </p>
              <p className="text-[var(--foreground-secondary)] leading-relaxed">
                <strong className="text-[var(--foreground)]">Current Status:</strong> Interactive Playbook Catalog Preview. Selecting a blueprint below previews its logic flow and simulated JSON dispatch contract without firing outbound webhooks or altering external infrastructure.
              </p>
            </div>
          </div>
        </div>

        {/* Playbook Templates */}
        <section className="space-y-4">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] tabular-nums">
              Automated Playbook Blueprints ({playbooks.length})
            </h2>
            <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
              Select a blueprint to inspect dispatch contract
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {playbooks.map((pb) => {
              const Icon = pb.icon;
              const isSelected = selectedPlaybook === pb.id;
              return (
                <button
                  key={pb.id}
                  type="button"
                  aria-pressed={isSelected}
                  onClick={() => setSelectedPlaybook(isSelected ? null : pb.id)}
                  className={`text-left rounded-2xl border p-5 transition-all cursor-pointer flex flex-col justify-between shadow-[var(--shadow-sm)] ${
                    isSelected
                      ? 'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)]/40 ring-1 ring-[var(--primary-orange)]/50'
                      : 'border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--primary-orange)]/40'
                  }`}
                >
                  <div className="w-full">
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="h-9 w-9 rounded-xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/25 text-[var(--accent-cyan)] flex items-center justify-center">
                        <Icon className="h-4 w-4" aria-hidden="true" />
                      </div>
                      <span className="text-[10px] font-mono font-semibold text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] px-2 py-0.5 rounded border border-[var(--accent-cyan)]/30">
                        {pb.tag}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                      {pb.name}
                    </h3>

                    <div className="mt-2.5 rounded-lg bg-[var(--surface-interactive)] px-2.5 py-1.5 text-[11px] font-mono text-[var(--foreground-secondary)] border border-[var(--border-subtle)]">
                      <strong className="text-[var(--foreground)]">Trigger:</strong> {pb.trigger}
                    </div>

                    <div className="mt-3 space-y-1.5">
                      <span className="text-[10px] uppercase font-bold tracking-wider text-[var(--muted-foreground)] block">
                        Execution Sequence
                      </span>
                      {pb.steps.map((step, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-1.5 text-xs text-[var(--foreground-secondary)] leading-snug"
                        >
                          <span className="text-[var(--primary-orange)] font-mono font-bold text-[10px] mt-0.5 tabular-nums">
                            {i + 1}.
                          </span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] w-full flex items-center justify-between text-xs font-semibold">
                    <span className="text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
                      {pb.statusLabel}
                    </span>
                    <span className="inline-flex items-center gap-1 text-[var(--primary-orange)]">
                      <span>{isSelected ? 'Selected' : 'Inspect'}</span>
                      <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {activeBlueprint && (
            <div className="rounded-2xl border border-[var(--primary-orange)]/40 bg-[var(--card-bg)] p-5 space-y-3 shadow-[var(--shadow-sm)]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--primary-orange)]">
                    Dry-Run Dispatch Contract Preview
                  </span>
                  <h3 className="text-sm font-bold text-[var(--foreground)] mt-0.5">
                    {activeBlueprint.name}
                  </h3>
                </div>
                <span className="rounded-md border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-[10px] font-mono text-[var(--foreground-secondary)]">
                  No outbound requests dispatched
                </span>
              </div>
              <pre className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background-secondary)] p-3.5 text-xs font-mono text-[var(--foreground)] overflow-x-auto">
                {activeBlueprint.samplePayload}
              </pre>
            </div>
          )}
        </section>
      </div>
    </AppShell>
  );
}
