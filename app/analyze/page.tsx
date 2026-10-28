'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import MessageAnalyzer from '@/components/MessageAnalyzer';
import AnalysisResult from '@/components/AnalysisResult';
import DocumentScanner from '@/components/DocumentScanner';
import DocumentScanResultComponent from '@/components/DocumentScanResult';
import FactCheckInput from '@/components/FactCheckInput';
import FactCheckCard from '@/components/FactCheckCard';
import SecurityTopology3D from '@/components/SecurityTopology3D';
import { ScamAnalysisResult } from '@/lib/scam-analyzer';
import { DocumentScanResult } from '@/lib/document-scanner';
import { FactCheckReport } from '@/lib/fact-checker/types';
import { saveSessionAnalysis } from '@/lib/session-store';
import DemoScenarios, { DemoScenario } from '@/components/DemoScenarios';
import {
  ShieldAlert,
  Radar,
  ArrowLeft,
  FileSearch,
  MessageSquare,
  UploadCloud,
  Globe,
  Link2,
} from 'lucide-react';
import Link from 'next/link';

function AnalyzePageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const tabParam = searchParams.get('tab');
  const [userSelectedTab, setUserSelectedTab] = useState<'message' | 'document' | 'factcheck' | null>(null);

  const activeTab = userSelectedTab ?? (tabParam === 'document' ? 'document' : tabParam === 'factcheck' ? 'factcheck' : 'message');
  const [messageResult, setMessageResult] = useState<ScamAnalysisResult | null>(null);
  const [documentResult, setDocumentResult] = useState<DocumentScanResult | null>(null);
  const [factCheckResult, setFactCheckResult] = useState<FactCheckReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const [selectedScenarioText, setSelectedScenarioText] = useState<string | null>(null);
  const [activeScenarioId, setActiveScenarioId] = useState<string | null>(null);

  const handleTabChange = (tab: 'message' | 'document' | 'factcheck') => {
    setUserSelectedTab(tab);
    router.replace(`/analyze?tab=${tab}`, { scroll: false });
  };

  const handleSelectScenario = (scenario: DemoScenario) => {
    setSelectedScenarioText(scenario.text);
    setActiveScenarioId(scenario.id);
    if (activeTab !== 'message') {
      handleTabChange('message');
    }
    setTimeout(() => {
      const textarea = document.getElementById('message-input') as HTMLTextAreaElement | null;
      if (textarea) {
        textarea.focus();
        textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 150);
  };

  const handleMessageComplete = (result: ScamAnalysisResult) => {
    setMessageResult(result);
    if (typeof window !== 'undefined') {
      const textarea = document.getElementById('message-input') as HTMLTextAreaElement | null;
      const text = textarea?.value || result.summary;
      saveSessionAnalysis(result, text);
    }
  };

  const handleDocumentComplete = (result: DocumentScanResult) => {
    setDocumentResult(result);
    if (typeof window !== 'undefined') {
      saveSessionAnalysis(
        result,
        `[${result.documentContent.filename}] ${result.summary}`
      );
    }
  };

  const handleResetMessage = () => {
    setMessageResult(null);
    const analyzerEl = document.getElementById('analyzer');
    if (analyzerEl) {
      analyzerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleResetDocument = () => {
    setDocumentResult(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const currentResult = activeTab === 'message' ? messageResult : documentResult;

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
              <span>AI Threat Analyzer &amp; Scanner</span>
            </h2>
            <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
              Inspect suspicious communications, SMS alerts, phishing emails, invoices, or screenshots using live Featherless Qwen inference.
            </p>
          </div>
          <div className="self-start sm:self-auto flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-950/30 px-3 py-1.5 text-xs text-cyan-300 font-mono">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Featherless &middot; Qwen3-VL-8B</span>
          </div>
        </div>

        {/* Interactive Demo Scenarios Section */}
        <DemoScenarios
          onSelectScenario={handleSelectScenario}
          activeScenarioId={activeScenarioId}
          disabled={isLoading}
        />

        {/* Sub-navigation Tabs: Message vs Document/Screenshot */}
        <div className="flex border-b border-white/10 gap-2">
          <button
            type="button"
            onClick={() => handleTabChange('message')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer ${
              activeTab === 'message'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <MessageSquare className="h-4 w-4" />
            <span>Direct Message Analysis</span>
          </button>
          <button
            type="button"
            onClick={() => handleTabChange('document')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer ${
              activeTab === 'document'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <FileSearch className="h-4 w-4" />
            <span>Document &amp; Screenshot Scanner</span>
            <span className="rounded-full bg-cyan-950 border border-cyan-500/30 px-1.5 py-0.2 text-[10px] font-mono text-cyan-300 font-normal">
              New
            </span>
          </button>
          <button
            type="button"
            onClick={() => handleTabChange('factcheck')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer ${
              activeTab === 'factcheck'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>Web Fact-Checker</span>
            <span className="rounded-full bg-blue-950 border border-blue-500/30 px-1.5 py-0.2 text-[10px] font-mono text-blue-300 font-normal">
              Research
            </span>
          </button>
          <Link
            href="/url-investigation"
            className="flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 border-transparent text-slate-400 hover:text-white"
          >
            <Link2 className="h-4 w-4 text-orange-400" />
            <span>URL Intelligence</span>
            <span className="rounded-full bg-orange-950 border border-orange-500/30 px-1.5 py-0.2 text-[10px] font-mono text-orange-300 font-normal">
              Standalone
            </span>
          </Link>
        </div>

        {/* Active Tab View */}
        {activeTab === 'message' ? (
          <>
            <MessageAnalyzer
              onAnalysisComplete={handleMessageComplete}
              isLoading={isLoading}
              setIsLoading={setIsLoading}
              prefilledText={selectedScenarioText}
            />

            {/* In-Flight Telemetry Scanner for Message */}
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

            {messageResult && !isLoading && (
              <AnalysisResult result={messageResult} onReset={handleResetMessage} />
            )}
          </>
        ) : activeTab === 'document' ? (
          <>
            <DocumentScanner
              onScanComplete={handleDocumentComplete}
              isScanning={isLoading}
              setIsScanning={setIsLoading}
            />

            {documentResult && !isLoading && (
              <DocumentScanResultComponent
                result={documentResult}
                onReset={handleResetDocument}
              />
            )}
          </>
        ) : (
          <>
            <FactCheckInput
              onReportComplete={setFactCheckResult}
              isLoading={isLoading}
              setIsLoading={setIsLoading}
            />

            {factCheckResult && !isLoading && (
              <FactCheckCard
                report={factCheckResult}
                onReset={() => setFactCheckResult(null)}
              />
            )}
          </>
        )}

        {/* 3D Multi-Layer Threat Topology Visualizer */}
        <div className="pt-4">
          <SecurityTopology3D
            currentStage={isLoading ? 'scanning' : currentResult ? 'complete' : 'idle'}
            riskLevel={currentResult?.riskLevel}
          />
        </div>
      </div>
    </AppShell>
  );
}

export default function AnalyzePage() {
  return (
    <Suspense
      fallback={
        <AppShell>
          <div className="p-8 text-center text-slate-400">Loading threat analyzer...</div>
        </AppShell>
      }
    >
      <AnalyzePageContent />
    </Suspense>
  );
}
