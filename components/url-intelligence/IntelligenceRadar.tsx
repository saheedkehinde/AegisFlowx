'use client';

import React from 'react';
import { UrlInvestigationReport } from '@/lib/url-investigation/types';

interface IntelligenceRadarProps {
  isLoading: boolean;
  activeStage?: number;
  report: UrlInvestigationReport | null;
  className?: string;
}

export default function IntelligenceRadar({
  isLoading,
  activeStage = 0,
  report,
  className = '',
}: IntelligenceRadarProps) {
  // Determine accent color and state
  const isHighRisk = report?.overallSeverity === 'high';
  const isMedRisk = report?.overallSeverity === 'medium';
  const isLowRisk = report?.overallSeverity === 'low';
  const isUncertain = report?.overallSeverity === 'uncertain';

  let ringColor = 'var(--primary-orange)';
  let glowColor = 'rgba(255, 121, 57, 0.25)';

  if (report) {
    if (isHighRisk) {
      ringColor = 'var(--status-critical)';
      glowColor = 'rgba(255, 100, 124, 0.35)';
    } else if (isMedRisk) {
      ringColor = 'var(--status-warning)';
      glowColor = 'rgba(255, 180, 94, 0.3)';
    } else if (isLowRisk) {
      ringColor = 'var(--status-success)';
      glowColor = 'rgba(66, 217, 160, 0.3)';
    } else if (isUncertain) {
      ringColor = 'var(--status-uncertain)';
      glowColor = 'rgba(155, 123, 255, 0.3)';
    }
  }

  return (
    <div
      className={`relative flex items-center justify-center select-none overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4 sm:p-6 shadow-md transition-colors ${className}`}
      aria-label="Threat Intelligence Radar Visualization"
    >
      {/* Background ambient radial illumination */}
      <div
        className="pointer-events-none absolute inset-0 opacity-40 blur-2xl transition-all duration-700"
        style={{
          background: `radial-gradient(circle at 50% 50%, ${glowColor} 0%, transparent 70%)`,
        }}
      />

      {/* Cyber Grid Texture */}
      <div className="pointer-events-none absolute inset-0 cyber-grid opacity-20" />

      {/* SVG Radar Instrument */}
      <div className="relative z-10 w-full max-w-[280px] sm:max-w-[320px] aspect-square flex items-center justify-center">
        <svg
          viewBox="0 0 300 300"
          className="w-full h-full"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {/* Sweep gradient for active scanning */}
            <linearGradient id="radarSweepGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--primary-orange)" stopOpacity="0.4" />
              <stop offset="50%" stopColor="var(--accent-cyan)" stopOpacity="0.15" />
              <stop offset="100%" stopColor="var(--primary-orange)" stopOpacity="0" />
            </linearGradient>

            <filter id="radarGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Outer Compass / Dial Ring */}
          <circle
            cx="150"
            cy="150"
            r="140"
            stroke="var(--border)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
          />

          {/* Concentric Calibration Rings */}
          <circle
            cx="150"
            cy="150"
            r="110"
            stroke="var(--border)"
            strokeWidth="1"
            opacity="0.8"
          />
          <circle
            cx="150"
            cy="150"
            r="80"
            stroke="var(--border)"
            strokeWidth="1"
            opacity="0.6"
          />
          <circle
            cx="150"
            cy="150"
            r="50"
            stroke="var(--border)"
            strokeWidth="1"
            strokeDasharray="2 4"
            opacity="0.5"
          />

          {/* Active Status Ring */}
          <circle
            cx="150"
            cy="150"
            r={report ? 110 : isLoading ? 80 : 50}
            stroke={ringColor}
            strokeWidth="2"
            opacity={report ? 0.9 : isLoading ? 0.8 : 0.4}
            filter={report || isLoading ? 'url(#radarGlow)' : undefined}
            className="transition-all duration-700"
          />

          {/* Axial Crosshairs */}
          <line
            x1="150"
            y1="10"
            x2="150"
            y2="290"
            stroke="var(--border)"
            strokeWidth="1"
            opacity="0.7"
          />
          <line
            x1="10"
            y1="150"
            x2="290"
            y2="150"
            stroke="var(--border)"
            strokeWidth="1"
            opacity="0.7"
          />

          {/* Diagonal Guides */}
          <line
            x1="50"
            y1="50"
            x2="250"
            y2="250"
            stroke="var(--border-subtle)"
            strokeWidth="0.75"
            strokeDasharray="2 4"
          />
          <line
            x1="250"
            y1="50"
            x2="50"
            y2="250"
            stroke="var(--border-subtle)"
            strokeWidth="0.75"
            strokeDasharray="2 4"
          />

          {/* Scanning Sweep Sector (active during loading) */}
          {isLoading && (
            <g className="origin-center animate-[spin_4s_linear_infinite] motion-reduce:animate-none">
              <path
                d="M 150 150 L 150 10 A 140 140 0 0 1 270 220 Z"
                fill="url(#radarSweepGrad)"
                opacity="0.6"
              />
              <line
                x1="150"
                y1="150"
                x2="150"
                y2="10"
                stroke="var(--primary-orange)"
                strokeWidth="2"
                filter="url(#radarGlow)"
              />
            </g>
          )}

          {/* Telemetry Target Blips / Detected Threat Nodes */}
          {report ? (
            <g className="transition-all duration-500">
              {/* Target Point Center */}
              <circle
                cx="150"
                cy="150"
                r="6"
                fill={ringColor}
                filter="url(#radarGlow)"
              />
              <circle
                cx="150"
                cy="150"
                r="18"
                stroke={ringColor}
                strokeWidth="1.5"
                opacity="0.5"
                className="animate-ping motion-reduce:animate-none"
              />

              {/* Orbital Finding Nodes */}
              {report.indicators.slice(0, 4).map((ind, i) => {
                const angles = [45, 135, 225, 315];
                const angle = angles[i] || 45;
                const rad = (angle * Math.PI) / 180;
                const dist = 70 + (i % 2) * 35;
                const cx = 150 + dist * Math.cos(rad);
                const cy = 150 + dist * Math.sin(rad);
                const nodeColor =
                  ind.severity === 'high'
                    ? 'var(--status-critical)'
                    : ind.severity === 'medium'
                    ? 'var(--status-warning)'
                    : 'var(--accent-cyan)';

                return (
                  <g key={ind.id || i} className="cursor-default">
                    <circle cx={cx} cy={cy} r="4" fill={nodeColor} filter="url(#radarGlow)" />
                    <circle cx={cx} cy={cy} r="8" stroke={nodeColor} strokeWidth="1" opacity="0.4" />
                    <line
                      x1="150"
                      y1="150"
                      x2={cx}
                      y2={cy}
                      stroke={nodeColor}
                      strokeWidth="0.75"
                      strokeDasharray="2 2"
                      opacity="0.3"
                    />
                  </g>
                );
              })}
            </g>
          ) : (
            /* Standby State Blip */
            <circle
              cx="150"
              cy="150"
              r="4"
              fill="var(--primary-orange)"
              opacity={isLoading ? 1 : 0.6}
            />
          )}

          {/* Radar Angle Calibration Ticks */}
          <text x="150" y="24" fill="var(--muted-foreground)" fontSize="8" fontFamily="monospace" textAnchor="middle">000°</text>
          <text x="276" y="153" fill="var(--muted-foreground)" fontSize="8" fontFamily="monospace" textAnchor="start">090°</text>
          <text x="150" y="284" fill="var(--muted-foreground)" fontSize="8" fontFamily="monospace" textAnchor="middle">180°</text>
          <text x="24" y="153" fill="var(--muted-foreground)" fontSize="8" fontFamily="monospace" textAnchor="end">270°</text>
        </svg>

        {/* Center Readout Overlay */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
          {isLoading ? (
            <div className="space-y-1">
              <span className="font-mono text-xs font-bold text-[var(--primary-orange)] animate-pulse block">
                TELEMETRY SCAN
              </span>
              <span className="font-mono text-[10px] text-[var(--foreground-secondary)] block">
                PHASE {activeStage + 1} OF 4
              </span>
            </div>
          ) : report ? (
            <div className="space-y-0.5 mt-8">
              <span
                className="font-mono text-xs font-extrabold uppercase tracking-widest block"
                style={{ color: ringColor }}
              >
                {report.overallSeverity} RISK
              </span>
              <span className="font-mono text-[10px] text-[var(--muted-foreground)] block">
                TARGET LOCKED
              </span>
            </div>
          ) : (
            <div className="space-y-0.5">
              <span className="font-mono text-[10px] uppercase font-bold text-[var(--muted-foreground)] block">
                STANDBY
              </span>
              <span className="font-mono text-[9px] text-[var(--muted-foreground)]/70 block">
                READY
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Coordinate & Sub-status Bar */}
      <div className="absolute bottom-2.5 left-4 right-4 flex items-center justify-between text-[9px] font-mono text-[var(--muted-foreground)] border-t border-[var(--border-subtle)] pt-1.5">
        <span>MODE: {isLoading ? 'MULTISTAGE_TELEMETRY' : report ? 'EVALUATION_RESOLVED' : 'PASSIVE_LISTENER'}</span>
        <span>INSTRUMENT: RADAR_V3B</span>
      </div>
    </div>
  );
}
