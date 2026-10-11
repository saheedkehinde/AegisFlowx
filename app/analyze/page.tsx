'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import MessageAnalyzer from '@/components/MessageAnalyzer';
import AnalysisResult from '@/components/AnalysisResult';
import SecurityTopology3D from '@/components/SecurityTopology3D';
import { ScamAnalysisResult } from '@/lib/scam-analyzer';
import { saveSessionAnalysis } from '@/lib/session-store';
import { ShieldAlert, Radar, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

export default function AnalyzePage() {
  const [analysisResult, setAnalysisResult] = useState<ScamAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalysisComplete = (result: ScamAnalysisResult) => {
    setAnalysisResult(result);
    // Track in current session storage
    if (typeof window !== 'undefined') {
      const textarea = document.getElementById('message-input') as HTMLTextAreaElement | null;
      const text = textarea?.value || result.summary;
      saveSessionAnalysis(result, text);
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    const analyzerEl = document.getElementById('analyzer');
    if (analyzerEl) {
      analyzerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Module Header Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/5 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <Link
                href="/"
                className="text-xs text-slate-400 hover:text-cyan-300 transition-colors inline-flex items-center gap-1"
              >
                <ArrowLeft className="h-3 w-3" />
                <span>Back to Overview</span>
              </Link>
            </div>
            <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
              <ShieldAlert className="h-7 w-7 text-cyan-400" />
              <span>AI Threat Analyzer</span>
            </h2>
            <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
              Inspect suspicious communications, SMS alerts, phishing emails, or invoice redirection lures using live Featherless Qwen inference.
            </p>
          </div>

          <div className="self-start sm:self-auto flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-950/30 px-3 py-1.5 text-xs text-cyan-300 font-mono">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Featherless &middot; Qwen3-VL-8B</span>
          </div>
        </div>

        {/* Existing Working Message Analyzer */}
        <MessageAnalyzer
          onAnalysisComplete={handleAnalysisComplete}
          isLoading={isLoading}
          setIsLoading={setIsLoading}
        />

        {/* In-Flight Telemetry Scanner */}
        {isLoading && (
          <div className="mx-auto max-w-5xl">
            <div className="rounded-2xl border border-cyan-500/30 bg-[#0d1322]/90 p-8 text-center backdrop-blur-xl shadow-2xl shadow-cyan-950/60 animate-pulse">
              <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 mb-4">
                <Radar className="h-7 w-7 animate-spin text-cyan-400" />
              </div>
              <h3 className="text-lg font-bold text-white">
                Deconstructing Threat Vectors...
              </h3>
              <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-md mx-auto">
                Analyzing linguistic urgency, domain reputation, social engineering patterns, and coercive cues.
              </p>
              <div className="mt-5 flex justify-center items-center gap-2 text-[11px] text-cyan-400 font-mono">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span>Streaming inference from Featherless AI (Qwen Instruction Model)</span>
              </div>
            </div>
          </div>
        )}

        {/* Existing Working Analysis Result */}
        {analysisResult && !isLoading && (
          <AnalysisResult result={analysisResult} onReset={handleReset} />
        )}

        {/* 3D Multi-Layer Threat Topology Visualizer */}
        <div className="pt-4">
          <SecurityTopology3D
            currentStage={isLoading ? 'scanning' : analysisResult ? 'complete' : 'idle'}
            riskLevel={analysisResult?.riskLevel}
          />
        </div>
      </div>
    </AppShell>
  );
}
