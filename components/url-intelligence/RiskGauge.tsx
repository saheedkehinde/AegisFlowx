'use client';

import React from 'react';
import { AlertOctagon, AlertTriangle, CheckCircle2, HelpCircle, Shield, Info } from 'lucide-react';
import ThreatBadge from '@/components/ui/ThreatBadge';

interface RiskGaugeProps {
  score: number;
  severity: 'high' | 'medium' | 'low' | 'uncertain';
  confidenceLevel: 'high' | 'moderate' | 'low';
  confidenceRationale: string;
  isUnlisted?: boolean;
}

export default function RiskGauge({
  score,
  severity,
  confidenceLevel,
  confidenceRationale,
  isUnlisted = false,
}: RiskGaugeProps) {
  // SVG circular gauge math (circumference = 2 * PI * r)
  const radius = 64;
  const stroke = 8;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  // Score clamped between 0 and 100
  const clampedScore = Math.min(100, Math.max(0, score));
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  let strokeColor = 'var(--status-critical)';
  let bgMeterColor = 'rgba(255, 100, 124, 0.15)';

  if (severity === 'medium') {
    strokeColor = 'var(--status-warning)';
    bgMeterColor = 'rgba(255, 180, 94, 0.15)';
  } else if (severity === 'low') {
    strokeColor = 'var(--status-success)';
    bgMeterColor = 'rgba(66, 217, 160, 0.15)';
  } else if (severity === 'uncertain') {
    strokeColor = 'var(--status-uncertain)';
    bgMeterColor = 'rgba(155, 123, 255, 0.15)';
  }

  const severityTitle =
    severity === 'high'
      ? 'CRITICAL / HIGH THREAT'
      : severity === 'medium'
      ? 'SUSPICIOUS / ELEVATED'
      : severity === 'low'
      ? 'LOW RISK / UNLISTED'
      : 'UNCERTAIN TELEMETRY';

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-sm flex flex-col justify-between space-y-5">
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-[var(--primary-orange)]" />
          <h2 className="text-xs sm:text-sm font-bold uppercase tracking-wider text-[var(--foreground)]">
            Risk Assessment Instrument
          </h2>
        </div>
        <ThreatBadge level={severity} score={score} size="sm" />
      </div>

      {/* Main Gauge & Numerical Metric */}
      <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-8 justify-center py-2">
        {/* Circular SVG Gauge */}
        <div className="relative flex items-center justify-center shrink-0">
          <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
            {/* Background Track */}
            <circle
              stroke={bgMeterColor}
              fill="transparent"
              strokeWidth={stroke}
              r={normalizedRadius}
              cx={radius}
              cy={radius}
            />
            {/* Foreground Score Ring */}
            <circle
              stroke={strokeColor}
              fill="transparent"
              strokeWidth={stroke}
              strokeDasharray={`${circumference} ${circumference}`}
              style={{ strokeDashoffset }}
              strokeLinecap="round"
              r={normalizedRadius}
              cx={radius}
              cy={radius}
              className="transition-all duration-1000 ease-out"
            />
          </svg>

          {/* Centered Score Number */}
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="font-mono text-3xl font-extrabold text-[var(--foreground)] tabular-nums tracking-tight">
              {score}
            </span>
            <span className="text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
              / 100
            </span>
          </div>
        </div>

        {/* Severity Classification and Confidence Rationale */}
        <div className="space-y-2 text-center sm:text-left flex-1 min-w-0">
          <div className="space-y-0.5">
            <span
              className="font-mono text-sm sm:text-base font-extrabold tracking-wide block"
              style={{ color: strokeColor }}
            >
              {severityTitle}
            </span>
            <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2 text-xs font-mono text-[var(--muted-foreground)]">
              <span>Confidence:</span>
              <span className="font-bold text-[var(--foreground)] uppercase">{confidenceLevel}</span>
              <span aria-hidden="true">&middot;</span>
              <span>Normalized Metric</span>
            </div>
          </div>

          <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
            {confidenceRationale}
          </p>
        </div>
      </div>

      {/* Unlisted Disclaimer / Caveat Notice */}
      <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-3 text-[11px] text-[var(--foreground-secondary)] flex items-start gap-2.5">
        <Info className="h-4 w-4 text-[var(--primary-orange)] shrink-0 mt-0.5" />
        <span className="leading-tight">
          <strong className="text-[var(--foreground)]">Intelligence Invariant:</strong> A low or unlisted rating verifies that this destination is not cataloged in active malware feeds. It does <em>not</em> guarantee that newly minted or targeted spearphishing lures are benign.
        </span>
      </div>
    </div>
  );
}
