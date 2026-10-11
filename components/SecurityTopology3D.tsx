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
      color: 'from-emerald-500/20 to-teal-500/10 border-emerald-500/30 text-emerald-300',
    },
    {
      id: 'l3',
      level: 'L3',
      name: 'IOC & Entity Extraction',
      description: 'Parses obfuscated URLs, typo-squatted domains, payment redirect tokens, and contact targets.',
      status: currentStage === 'scanning' || currentStage === 'complete' ? 'active' : 'idle',
      color: 'from-cyan-500/20 to-blue-500/10 border-cyan-500/30 text-cyan-300',
    },
    {
      id: 'l2',
      level: 'L2',
      name: 'Behavioral & Urgency Heuristics',
      description: 'Detects psychological coercion, manufactured deadlines, authority spoofing, and BEC triggers.',
      status: currentStage === 'scanning' || currentStage === 'complete' ? 'active' : 'idle',
      color: 'from-blue-500/20 to-indigo-500/10 border-blue-500/30 text-blue-300',
    },
    {
      id: 'l1',
      level: 'L1',
      name: 'Ingress & Untrusted Boundary',
      description: 'Sanitizes raw text, enforces prompt injection isolation, and redacts sensitive PII.',
      status: 'active',
      color: 'from-indigo-500/20 to-slate-500/10 border-indigo-500/30 text-indigo-300',
    },
  ];

  return (
    <div className="relative rounded-2xl border border-white/10 bg-[#0a0f1d]/90 p-5 sm:p-6 backdrop-blur-xl shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-white/5 pb-4 mb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <h3 className="text-sm font-bold tracking-tight text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              <span>Multi-Layer Threat Inspection Topology</span>
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Architectural depth breakdown: how untrusted submissions traverse defensive security barriers.
          </p>
        </div>

        <span className="self-start sm:self-auto rounded bg-cyan-500/10 px-2 py-0.5 text-[11px] font-mono text-cyan-400 border border-cyan-500/20">
          3D Perspective View
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
                <div
                  key={layer.id}
                  onMouseEnter={() => setActiveLayer(index)}
                  onMouseLeave={() => setActiveLayer(null)}
                  className={`absolute w-52 h-14 rounded-xl border bg-gradient-to-r shadow-lg transition-all duration-300 cursor-pointer flex items-center justify-between px-3.5 ${
                    layer.color
                  } ${
                    isHovered
                      ? 'scale-105 ring-2 ring-cyan-400/50 shadow-cyan-500/20'
                      : 'hover:scale-102'
                  }`}
                  style={{
                    transform: `rotateX(54deg) rotateZ(-32deg) translateY(${yOffset}px) translateZ(${zOffset}px)`,
                    zIndex: 4 - index,
                  }}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-white bg-black/40 px-1.5 py-0.5 rounded border border-white/10">
                      {layer.level}
                    </span>
                    <span className="text-xs font-semibold text-slate-200 truncate max-w-[110px]">
                      {layer.name.split(' ')[0]}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        layer.status === 'active' ? 'bg-cyan-400' : 'bg-slate-500'
                      }`}
                    />
                  </div>
                </div>
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
                className={`rounded-xl border p-3 transition-all duration-200 cursor-pointer ${
                  isHovered
                    ? 'border-cyan-500/40 bg-cyan-950/20 ring-1 ring-cyan-500/30'
                    : 'border-white/5 bg-slate-900/40 hover:border-white/15'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] font-bold text-cyan-300 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                      {layer.level}
                    </span>
                    <span className="text-xs font-bold text-white">
                      {layer.name}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase">
                    {layer.status === 'active' ? 'Enforced' : 'Standby'}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
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
