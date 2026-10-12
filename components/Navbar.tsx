'use client';

import React from 'react';
import { ShieldAlert, Cpu, Terminal, Radio } from 'lucide-react';

export default function Navbar() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/5 bg-[#070b14]/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3.5 sm:px-6 lg:px-8">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 shadow-lg shadow-cyan-500/20 ring-1 ring-white/20">
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold tracking-tight text-white">
                Aegis<span className="text-cyan-400">Flow</span>
              </span>
              <span className="hidden rounded bg-cyan-500/10 px-2 py-0.5 text-[11px] font-mono tracking-wide text-cyan-400 border border-cyan-500/20 sm:inline-block">
                Intelligence Platform
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Cybersecurity &amp; Scam Triage</p>
          </div>
        </div>

        {/* Center / Navigation Links */}
        <nav className="hidden md:flex items-center gap-6 text-xs font-semibold uppercase tracking-wider text-slate-400">
          <a
            href="#analyzer"
            className="transition-colors hover:text-cyan-300"
          >
            Analyzer
          </a>
          <a
            href="#topology"
            className="transition-colors hover:text-cyan-300"
          >
            3D Topology
          </a>
          <a
            href="#how-it-works"
            className="transition-colors hover:text-cyan-300"
          >
            Workflow
          </a>
          <a
            href="#threat-vectors"
            className="transition-colors hover:text-cyan-300"
          >
            Threat Vectors
          </a>
        </nav>

        {/* Right Status Indicator */}
        <div className="flex items-center gap-3">
          {/* Operational status */}
          <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-950/40 px-3 py-1 text-xs text-emerald-300 shadow-sm shadow-emerald-950/50">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="hidden sm:inline font-mono font-medium text-[11px]">Active Defense</span>
            <span className="sm:hidden font-medium text-[11px]">Active</span>
          </div>

          {/* Model badge */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-400 border border-white/10 px-2.5 py-1 rounded-md bg-white/[0.02]">
            <Cpu className="h-3.5 w-3.5 text-cyan-400" />
            <span className="font-mono text-[11px]">Featherless &middot; Qwen3</span>
          </div>
        </div>
      </div>
    </header>
  );
}
