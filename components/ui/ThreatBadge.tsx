'use client';

import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
} from 'lucide-react';

export type ThreatLevel = 'high' | 'medium' | 'low' | 'uncertain' | string;

export interface ThreatBadgeProps {
  level?: ThreatLevel | null;
  score?: number | null;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'badge' | 'banner';
  className?: string;
}

export function normalizeThreatLevel(level?: ThreatLevel | null): 'high' | 'medium' | 'low' | 'uncertain' {
  if (!level || typeof level !== 'string') return 'uncertain';
  const clean = level.trim().toLowerCase();
  if (clean.includes('high')) return 'high';
  if (clean.includes('medium') || clean.includes('elevated') || clean.includes('suspicious')) return 'medium';
  if (clean.includes('low') || clean.includes('safe') || clean.includes('benign')) return 'low';
  return 'uncertain';
}

export default function ThreatBadge({
  level,
  score,
  showScore = false,
  size = 'md',
  variant = 'badge',
  className = '',
}: ThreatBadgeProps) {
  const normalized = normalizeThreatLevel(level);

  const configs = {
    high: {
      label: 'HIGH RISK',
      colorClasses: 'text-red-400 bg-red-950/70 border-red-500/40 shadow-sm shadow-red-950/50',
      icon: AlertOctagon,
    },
    medium: {
      label: 'MEDIUM RISK',
      colorClasses: 'text-amber-400 bg-amber-950/70 border-amber-500/40 shadow-sm shadow-amber-950/50',
      icon: AlertTriangle,
    },
    low: {
      label: 'LOW RISK',
      colorClasses: 'text-emerald-400 bg-emerald-950/70 border-emerald-500/40 shadow-sm shadow-emerald-950/50',
      icon: CheckCircle2,
    },
    uncertain: {
      label: 'UNCERTAIN',
      colorClasses: 'text-purple-400 bg-purple-950/70 border-purple-500/40 shadow-sm shadow-purple-950/50',
      icon: HelpCircle,
    },
  };

  const config = configs[normalized];
  const IconComponent = config.icon;

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 gap-2',
  }[size];

  const iconSizes = {
    sm: 'h-3 w-3',
    md: 'h-3.5 w-3.5',
    lg: 'h-4 w-4',
  }[size];

  const hasScore = showScore && typeof score === 'number' && !isNaN(score);

  return (
    <span
      className={`inline-flex items-center font-mono font-semibold rounded-lg border transition-colors ${config.colorClasses} ${sizeClasses} ${className}`}
      aria-label={`Threat assessment: ${config.label}${hasScore ? `, Severity Index ${score} out of 100` : ''}`}
    >
      <IconComponent className={`${iconSizes} shrink-0`} aria-hidden="true" />
      <span>{config.label}</span>
      {hasScore && (
        <span className="font-normal text-white/90 ml-0.5">
          ({score}/100)
        </span>
      )}
    </span>
  );
}
