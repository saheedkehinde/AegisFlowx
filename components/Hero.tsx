'use client';

import React from 'react';
import { ShieldCheck, AlertTriangle, Eye, ArrowDown, Lock, CheckCircle2 } from 'lucide-react';

export default function Hero() {
  return (
    <section className="relative overflow-hidden pt-12 pb-10 sm:pt-16 sm:pb-12 text-center">
      {/* Background radial gradient glow */}
      <div className="pointer-events-none absolute inset-0 -z-10 flex items-center justify-center">
        <div className="h-[360px] w-[650px] rounded-full bg-gradient-to-tr from-blue-600/20 via-indigo-600/15 to-violet-600/10 blur-[100px]" />
      </div>

      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        {/* Hackathon category kicker */}
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-500/25 bg-blue-950/40 px-3.5 py-1 text-xs font-medium text-blue-300">
          <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
          <span>ForgeHacks 2026 Project &middot; AI + Cybersecurity</span>
        </div>

        {/* Headline */}
        <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl md:text-6xl">
          Think Before You <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-300 bg-clip-text text-transparent">Trust</span>.
        </h1>

        {/* Subtitle */}
        <p className="mt-4 text-xl font-medium text-slate-200 sm:text-2xl">
          Your AI-powered second opinion for suspicious messages.
        </p>

        {/* Supporting text */}
        <p className="mx-auto mt-3 max-w-2xl text-base text-slate-400 sm:text-lg leading-relaxed">
          Uncover warning signs, understand the evidence, and discover safer next steps before you respond.
        </p>

        {/* Trust pillars / highlights */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-4 text-xs sm:text-sm text-slate-300">
          <div className="flex items-center gap-2 rounded-lg border border-white/5 bg-slate-900/60 px-3.5 py-2">
            <Lock className="h-4 w-4 text-blue-400" />
            <span>Zero Personal Data Stored</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-white/5 bg-slate-900/60 px-3.5 py-2">
            <Eye className="h-4 w-4 text-cyan-400" />
            <span>Evidence-Backed Explanations</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-white/5 bg-slate-900/60 px-3.5 py-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span>Actionable Defense Checklist</span>
          </div>
        </div>
      </div>
    </section>
  );
}
