'use client';

import React, { useState } from 'react';
import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import MessageAnalyzer from '@/components/MessageAnalyzer';
import AnalysisResult from '@/components/AnalysisResult';
import HowItWorks from '@/components/HowItWorks';
import Footer from '@/components/Footer';
import { ScamAnalysisResult } from '@/lib/scam-analyzer';
import { ShieldCheck, Radar, Lock, Sparkles } from 'lucide-react';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<ScamAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalysisComplete = (result: ScamAnalysisResult) => {
    setAnalysisResult(result);
  };

  const handleReset = () => {
    setAnalysisResult(null);
    const analyzerEl = document.getElementById('analyzer');
    if (analyzerEl) {
      analyzerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 selection:bg-blue-600 selection:text-white relative overflow-x-hidden cyber-grid">
      {/* Top Navbar */}
      <Navbar />

      <main className="relative z-10 pb-16">
        {/* Hero Section */}
        <Hero />

        {/* Message Analyzer Card */}
        <MessageAnalyzer
          onAnalysisComplete={handleAnalysisComplete}
          isLoading={isLoading}
          setIsLoading={setIsLoading}
        />

        {/* Loading State Overlay / Card if in flight */}
        {isLoading && (
          <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 mt-10">
            <div className="rounded-2xl border border-blue-500/30 bg-[#0d1322]/90 p-8 text-center backdrop-blur-xl shadow-2xl shadow-blue-950/60 animate-pulse">
              <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-600/20 text-blue-400 border border-blue-500/30 mb-4">
                <Radar className="h-7 w-7 animate-spin text-blue-400" />
              </div>
              <h3 className="text-lg font-bold text-white">
                Deconstructing Threat Vectors...
              </h3>
              <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-md mx-auto">
                Analyzing linguistic urgency, domain reputation, social engineering patterns, and coercive cues.
              </p>
              <div className="mt-5 flex justify-center items-center gap-2 text-[11px] text-blue-400 font-mono">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-400 animate-ping" />
                <span>Analyzing via Featherless AI (Qwen Instruction Model)</span>
              </div>
            </div>
          </div>
        )}

        {/* Analysis Result (if available and not currently re-fetching) */}
        {analysisResult && !isLoading && (
          <AnalysisResult result={analysisResult} onReset={handleReset} />
        )}

        {/* How It Works Section */}
        <HowItWorks />
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}
