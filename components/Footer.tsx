'use client';

import React from 'react';
import { ShieldAlert, Heart, ExternalLink } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="mt-20 border-t border-white/5 bg-[#05080f] py-12 text-slate-400">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-8 pb-8 border-b border-white/5">
          {/* Brand & Mission */}
          <div className="max-w-md">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-600 shadow-md shadow-cyan-500/20">
                <ShieldAlert className="h-4 w-4 text-white" />
              </div>
              <span className="text-base font-bold text-white tracking-tight">
                Aegis<span className="text-cyan-400">Flow</span>
              </span>
            </div>
            <p className="mt-3 text-xs sm:text-sm text-slate-400 leading-relaxed">
              Empowering individuals and teams with instant AI second opinions to spot social engineering, phishing campaigns, and deceptive payment schemes before harm occurs.
            </p>
          </div>

          {/* Hackathon Context & Links */}
          <div className="flex flex-col sm:flex-row gap-8 text-xs">
            <div>
              <h5 className="font-semibold text-white tracking-wider uppercase text-[11px] mb-2.5">
                System Details
              </h5>
              <ul className="space-y-1.5 text-slate-400">
                <li>Platform: <strong className="text-slate-300">AegisFlow Intelligence</strong></li>
                <li>Track: <strong className="text-slate-300">AI + Cybersecurity</strong></li>
                <li>Target Model: <span className="text-cyan-400 font-mono">Qwen/Qwen3-VL-8B-Instruct</span></li>
                <li>Provider: <span className="text-slate-300">Featherless AI (https://api.featherless.ai/v1)</span></li>
              </ul>
            </div>

            <div>
              <h5 className="font-semibold text-white tracking-wider uppercase text-[11px] mb-2.5">
                Cyber Resources
              </h5>
              <ul className="space-y-1.5 text-slate-400">
                <li>
                  <a
                    href="https://www.cisa.gov/stopransomware"
                    target="_blank"
                    rel="noreferrer"
                    className="hover:text-blue-400 transition-colors inline-flex items-center gap-1"
                  >
                    <span>CISA Cybersecurity Guides</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
                <li>
                  <a
                    href="https://reportfraud.ftc.gov/"
                    target="_blank"
                    rel="noreferrer"
                    className="hover:text-blue-400 transition-colors inline-flex items-center gap-1"
                  >
                    <span>FTC Fraud Reporting Portal</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
                <li>
                  <a
                    href="https://apwg.org/"
                    target="_blank"
                    rel="noreferrer"
                    className="hover:text-blue-400 transition-colors inline-flex items-center gap-1"
                  >
                    <span>Anti-Phishing Working Group</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Mandatory Disclaimer */}
        <div className="mt-8 pt-2">
          <div className="rounded-lg border border-white/5 bg-white/[0.015] p-4 text-xs text-slate-500 leading-relaxed">
            <strong className="text-slate-400">Mandatory Security Disclaimer: </strong>
            AegisFlow is an advisory heuristic and artificial intelligence analysis tool intended for informational educational use. It cannot guarantee whether a communication is 100% legitimate or fraudulent. Attackers constantly alter tactics, and sophisticated threats can evade pattern recognition. Always independently verify suspicious requests directly with the verified institution using known, trusted official contact numbers or authentic mobile applications.
          </div>

          <div className="mt-6 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
            <p>&copy; {new Date().getFullYear()} AegisFlow &middot; Built for ForgeHacks 2026.</p>
            <p>Designed for real-world cyber resilience.</p>
          </div>
        </div>
      </div>
    </footer>
  );
}
