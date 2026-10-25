'use client';

import React from 'react';
import {
  Briefcase,
  Truck,
  Landmark,
  ArrowRight,
} from 'lucide-react';

export interface DemoScenario {
  id: string;
  title: string;
  tag: string;
  objective: string;
  icon: React.ElementType;
  text: string;
}

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: 'executive-wire-fraud',
    title: 'Executive Wire Fraud',
    tag: 'Executive Impersonation (BEC)',
    objective: 'Urgency pressure, authority impersonation, and attempts to bypass dual-control finance workflows.',
    icon: Briefcase,
    text: "URGENT & CONFIDENTIAL: Hi team, I'm currently in an offsite executive board meeting with our acquisition partners and cannot take voice calls. We need to immediately execute a time-sensitive closing wire of $84,500.00 to escrow account ACCT-99214-ESC at Apex Commercial Trust to lock in the final contract before 4:00 PM EST. Due to strict NDA requirements, bypass the standard secondary finance verification queue for this transaction—I will sign off on the retro-approval directly with audit tomorrow morning. Wire routing details attached in secure portal: https://apex-escrow-closing.internal-auth.net/wire-instructions",
  },
  {
    id: 'delivery-sms-phishing',
    title: 'Delivery SMS Phishing',
    tag: 'Delivery Smishing',
    objective: 'Deceptive delivery notifications, urgent package holds, unexpected recalculation fees, and spoofed clearance links.',
    icon: Truck,
    text: "GLOBAL EXPRESS LOGISTICS ALERT: Parcel #GX-88204-91 cannot be scheduled for door delivery due to missing street address digits. A redelivery hold has been placed on your package. Please confirm your delivery address and authorize the $2.15 customs recalculation fee within 12 hours to avoid return to regional sender: https://parcel-track-update.delivery-hold-status.biz/clearance",
  },
  {
    id: 'bank-account-suspension',
    title: 'Bank Account Suspension',
    tag: 'Credential Harvesting',
    objective: 'Synthetic security panic, simulated access restriction, and social engineering designed to harvest One-Time Passwords (OTPs).',
    icon: Landmark,
    text: "SECURITY NOTICE: Immediate action required. Unusual access attempts were detected from an unrecognized IP address in foreign jurisdiction. Your online banking profile and debit privileges have been restricted to protect assets. To restore access and verify identity, do not share your incoming verification code with anyone. Authenticate your session and input your 6-digit one-time passcode immediately at: https://secure-account-verification.cust-safety-auth.com/login",
  },
];

interface DemoScenariosProps {
  onSelectScenario: (scenario: DemoScenario) => void;
  activeScenarioId?: string | null;
  disabled?: boolean;
}

export default function DemoScenarios({
  onSelectScenario,
  activeScenarioId,
  disabled = false,
}: DemoScenariosProps) {
  return (
    <section
      aria-label="Interactive Demo Scenarios"
      className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-4 sm:p-6 shadow-sm space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--primary-orange)] bg-[var(--surface-soft-orange)] px-2 py-0.5 rounded border border-[var(--primary-orange)]/30">
              Interactive Demonstrations
            </span>
            <span className="text-xs text-[var(--muted-foreground)] font-medium hidden sm:inline">
              &middot; 3 Curated Scenarios
            </span>
          </div>
          <h3 className="text-base sm:text-lg font-bold text-[var(--foreground)] mt-1">
            Try a Demo Scenario
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5 max-w-2xl">
            Select a fictional threat scenario to populate the analyzer and evaluate behavioral detection heuristics before submitting.
          </p>
        </div>

        <span className="text-[11px] font-mono text-[var(--muted-foreground)] self-start sm:self-auto">
          Fictional training telemetry
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {DEMO_SCENARIOS.map((scenario) => {
          const Icon = scenario.icon;
          const isSelected = activeScenarioId === scenario.id;

          return (
            <div
              key={scenario.id}
              className={`group relative rounded-xl border p-4 transition-all duration-200 flex flex-col justify-between ${
                isSelected
                  ? 'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)] ring-1 ring-[var(--primary-orange)]/50 shadow-md'
                  : 'border-[var(--border)] bg-[var(--surface)] hover:border-[var(--primary-orange)]/40 hover:bg-[var(--surface-interactive)]'
              }`}
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="h-8 w-8 rounded-lg bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Icon className="h-4 w-4" />
                  </div>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)] bg-[var(--surface-interactive)] px-2 py-0.5 rounded border border-[var(--border)]">
                    {scenario.tag}
                  </span>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors">
                    {scenario.title}
                  </h4>
                  <p className="mt-1 text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                    <strong className="text-[var(--foreground)]">Objective:</strong> {scenario.objective}
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => onSelectScenario(scenario)}
                  className={`w-full inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none disabled:opacity-50 min-h-[38px] ${
                    isSelected
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                      : 'border border-[var(--border)] bg-[var(--surface)] text-[var(--primary-orange)] hover:bg-[var(--primary-orange)] hover:text-[var(--primary-foreground)] hover:border-[var(--primary-orange)] shadow-sm'
                  }`}
                >
                  <span>{isSelected ? 'Scenario Loaded' : 'Load Scenario'}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
