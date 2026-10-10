'use client';

import React from 'react';
import { ShieldAlert, ShieldCheck, ExternalLink, Cpu } from 'lucide-react';

export default function Navbar() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/5 bg-[#070b14]/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3.5 sm:px-6 lg:px-8">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-blue-600 via-indigo-600 to-blue-700 shadow-lg shadow-blue-500/20 ring-1 ring-white/20">
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold tracking-tight text-white">
                ScamShield<span className="text-blue-400"> AI</span>
              </span>
              <span className="hidden rounded bg-blue-500/10 px-2 py-0.5 text-[11px] font-medium tracking-wide text-blue-400 border border-blue-500/20 sm:inline-block">
                ForgeHacks 2026
              </span>
            </div>
            <p className="text-[11px] text-slate-400">AI + Cybersecurity Track</p>
          </div>
        </div>

        {/* Center / Navigation Links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
          <a
            href="#analyzer"
            className="transition-colors hover:text-white hover:underline underline-offset-4 decoration-blue-500/50"
          >
            Analyzer
          </a>
          <a
            href="#how-it-works"
            className="transition-colors hover:text-white hover:underline underline-offset-4 decoration-blue-500/50"
          >
            How It Works
          </a>
          <a
            href="#threat-vectors"
            className="transition-colors hover:text-white hover:underline underline-offset-4 decoration-blue-500/50"
          >
            Threat Vectors
          </a>
        </nav>

        {/* Right Status Indicator */}
        <div className="flex items-center gap-3">
          {/* Live digital safety status */}
          <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-950/40 px-3 py-1 text-xs text-emerald-300 shadow-sm shadow-emerald-950/50">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="hidden sm:inline font-medium">Your digital safety matters</span>
            <span className="sm:hidden font-medium">Active Defense</span>
          </div>

          {/* Model badge */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-400 border border-white/10 px-2.5 py-1 rounded-md bg-white/[0.02]">
            <Cpu className="h-3.5 w-3.5 text-blue-400" />
            <span>Featherless AI &middot; Qwen</span>
          </div>
        </div>
      </div>
    </header>
  );
}
