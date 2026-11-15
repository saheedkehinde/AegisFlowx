'use client';

import React, { useState } from 'react';
import { Layers, ShieldCheck, Cpu, AlertTriangle, ArrowRight } from 'lucide-react';

interface TopologyLayer {
  id: string;
  level: string;
  name: string;
  description: string;
  status: 'active' | 'analyzing' | 'idle';
  color: string;
}

interface SecurityTopology3DProps {
  currentStage?: 'idle' | 'scanning' | 'complete';
  riskLevel?: 'high' | 'medium' | 'low' | 'uncertain';
}

export default function SecurityTopology3D({
  currentStage = 'idle',
  riskLevel,
}: SecurityTopology3DProps) {
  const [activeLayer, setActiveLayer] = useState<number | null>(null);

  const layers: TopologyLayer[] = [
    {
      id: 'l4',
      level: 'L4',
      name: 'Advisory & Policy Mitigation',
      description: 'Generates non-destructive action checklist, containment steps, and official verification paths.',
      status: currentStage === 'complete' ? 'active' : 'idle',
      color: 'bg-[var(--surface)] border-[var(--status-success-border)] text-[var(--status-success)]',
    },
    {
      id: 'l3',
      level: 'L3',
      name: 'IOC & Entity Extraction',
      description: 'Parses obfuscated URLs, typo-squatted domains, payment redirect tokens, and contact targets.',
      status: currentStage === 'scanning' || currentStage === 'complete' ? 'active' : 'idle',
      color: 'bg-[var(--surface)] border-[var(--accent-cyan)]/35 text-[var(--accent-cyan)]',
    },
    {
      id: 'l2',
      level: 'L2',
      name: 'Behavioral & Urgency Heuristics',
      description: 'Detects psychological coercion, manufactured deadlines, authority spoofing, and BEC triggers.',
      status: currentStage === 'scanning' || currentStage === 'complete' ? 'active' : 'idle',
      color: 'bg-[var(--surface)] border-[var(--primary-orange)]/35 text-[var(--primary-orange)]',
    },
    {
      id: 'l1',
      level: 'L1',
      name: 'Ingress & Untrusted Boundary',
      description: 'Sanitizes raw text, enforces prompt injection isolation, and redacts sensitive PII.',
      status: 'active',
      color: 'bg-[var(--surface)] border-[var(--accent-violet)]/35 text-[var(--accent-violet)]',
    },
  ];

  return (
    <div className="relative rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-6 shadow-[var(--shadow-md)]">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--border-subtle)] pb-4 mb-5">
        <div>
          <h3 className="text-sm font-bold tracking-tight text-[var(--foreground)] flex items-center gap-2 font-[family-name:var(--font-display)]">
            <Layers className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>Multi-Layer Threat Inspection Topology</span>
          </h3>
          <p className="text-xs text-[var(--foreground-secondary)] mt-0.5">
            Architectural depth breakdown: how untrusted submissions traverse defensive security barriers.
          </p>
        </div>

        <span className="self-start sm:self-auto rounded bg-[var(--accent-cyan-subtle)] px-2.5 py-0.5 text-[11px] font-mono font-semibold text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/25">
          4-Layer Pipeline
        </span>
      </div>

      {/* Isometric 3D Layer Stack */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Visual 3D Stack */}
        <div className="lg:col-span-5 flex justify-center py-4">
          <div
            className="relative w-64 h-56 flex flex-col items-center justify-center transition-transform duration-300"
            style={{
              perspective: '800px',
            }}
          >
            {layers.map((layer, index) => {
              const isHovered = activeLayer === index;
              const yOffset = (index - 1.5) * 36;
              const zOffset = (3 - index) * 20;

              return (
                <button
                  type="button"
                  key={layer.id}
                  onMouseEnter={() => setActiveLayer(index)}
                  onMouseLeave={() => setActiveLayer(null)}
                  onFocus={() => setActiveLayer(index)}
                  onBlur={() => setActiveLayer(null)}
                  className={`absolute w-52 h-14 rounded-xl border shadow-md transition-all duration-300 cursor-pointer flex items-center justify-between px-3.5 ${
                    layer.color
                  } ${
                    isHovered
                      ? 'scale-105 ring-2 ring-[var(--primary-orange)]/60'
                      : 'hover:scale-102'
                  }`}
                  style={{
                    transform: `rotateX(54deg) rotateZ(-32deg) translateY(${yOffset}px) translateZ(${zOffset}px)`,
                    zIndex: 4 - index,
                  }}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[var(--foreground)] bg-[var(--surface-interactive)] px-1.5 py-0.5 rounded border border-[var(--border)]">
                      {layer.level}
                    </span>
                    <span className="text-xs font-semibold text-[var(--foreground)] truncate max-w-[110px]">
                      {layer.name.split(' ')[0]}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{
                        backgroundColor:
                          layer.status === 'active'
                            ? 'var(--accent-cyan)'
                            : 'var(--muted-foreground)',
                      }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Detailed Legend / Active Layer Inspector */}
        <div className="lg:col-span-7 space-y-2">
          {layers.map((layer, index) => {
            const isHovered = activeLayer === index;
            return (
              <div
                key={layer.id}
                onMouseEnter={() => setActiveLayer(index)}
                onMouseLeave={() => setActiveLayer(null)}
                className={`rounded-xl border p-3 transition-all duration-200 ${
                  isHovered
                    ? 'border-[var(--primary-orange)]/50 bg-[var(--surface-soft-orange)]'
                    : 'border-[var(--border)] bg-[var(--surface-interactive)] hover:border-[var(--border-strong)]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] font-bold text-[var(--accent-cyan)] bg-[var(--accent-cyan-subtle)] px-1.5 py-0.5 rounded border border-[var(--accent-cyan)]/25">
                      {layer.level}
                    </span>
                    <span className="text-xs font-bold text-[var(--foreground)]">
                      {layer.name}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-[var(--muted-foreground)] uppercase">
                    {layer.status === 'active' ? 'Enforced' : 'Standby'}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-[var(--foreground-secondary)] leading-relaxed">
                  {layer.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
