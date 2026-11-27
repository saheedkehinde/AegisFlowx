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
import PageHeader from '@/components/ui/PageHeader';
import QuotaStatusBanner from '@/components/QuotaStatusBanner';
import { useQuota } from '@/hooks/use-quota';

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
  const {
    quota,
    loading: quotaLoading,
    error: quotaError,
    errorCode: quotaErrorCode,
    requiresVerification,
  } = useQuota();

  const activeCapability =
    activeTab === 'message'
      ? 'message_analysis'
      : activeTab === 'document'
      ? 'document_scan'
      : 'fact_check';

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
      saveSessionAnalysis(result, text, 'message');
    }
  };

  const handleDocumentComplete = (result: DocumentScanResult) => {
    setDocumentResult(result);
    if (typeof window !== 'undefined') {
      const mime = (result.documentContent?.mimeType || '').toLowerCase();
      const filename = (result.documentContent?.filename || '').toLowerCase();
      const docType =
        mime.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/.test(filename)
          ? 'screenshot'
          : 'document';
      saveSessionAnalysis(
        result,
        `[${result.documentContent.filename}] ${result.summary}`,
        docType
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
      <div className="space-y-8 max-w-7xl mx-auto pb-12">
        {/* Module Header Banner */}
        <PageHeader
          breadcrumbLabel="Analyze"
          title="AI Threat Analyzer & Scanner"
          description="Inspect suspicious communications, SMS alerts, phishing emails, invoices, or screenshots using Aegis AI threat analysis."
          icon={ShieldAlert}
          badgeText="Aegis AI · Threat Engine"
          badgeVariant="cyan"
        />

        {/* Interactive Demo Scenarios Section */}
        <DemoScenarios
          onSelectScenario={handleSelectScenario}
          activeScenarioId={activeScenarioId}
          disabled={isLoading}
        />

        {/* Authoritative Server Quota Allowance Banner */}
        <QuotaStatusBanner
          quota={quota}
          loading={quotaLoading}
          error={quotaError}
          errorCode={quotaErrorCode}
          requiresVerification={requiresVerification}
          activeCapability={activeCapability}
        />

        {/* Sub-navigation Tabs: Message vs Document/Screenshot vs Fact-Check */}
        <div
          role="tablist"
          aria-label="Analysis modes"
          className="flex border-b border-[var(--border)] gap-1 sm:gap-2 overflow-x-auto"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'message'}
            onClick={() => handleTabChange('message')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] ${
              activeTab === 'message'
                ? 'border-[var(--primary-orange)] text-[var(--primary-orange)]'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
            }`}
          >
            <MessageSquare className="h-4 w-4" />
            <span>Direct Message Analysis</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'document'}
            onClick={() => handleTabChange('document')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] ${
              activeTab === 'document'
                ? 'border-[var(--primary-orange)] text-[var(--primary-orange)]'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
            }`}
          >
            <FileSearch className="h-4 w-4" />
            <span>Document &amp; Screenshot Scanner</span>
            <span className="rounded bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-1.5 py-0.5 text-[10px] font-mono text-[var(--accent-cyan)] font-semibold">
              OCR
            </span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'factcheck'}
            onClick={() => handleTabChange('factcheck')}
            disabled={isLoading}
            className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 cursor-pointer whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] ${
              activeTab === 'factcheck'
                ? 'border-[var(--primary-orange)] text-[var(--primary-orange)]'
                : 'border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>Web Fact-Checker</span>
            <span className="rounded bg-[var(--accent-violet-subtle)] border border-[var(--accent-violet)]/30 px-1.5 py-0.5 text-[10px] font-mono text-[var(--accent-violet)] font-semibold">
              Research
            </span>
          </button>
          <Link
            href="/url-investigation"
            className="flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-semibold transition-all border-b-2 border-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] whitespace-nowrap shrink-0"
          >
            <Link2 className="h-4 w-4 text-[var(--primary-orange)]" />
            <span>URL Intelligence</span>
            <span className="rounded bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 px-1.5 py-0.5 text-[10px] font-mono text-[var(--primary-orange)] font-semibold">
              Dedicated
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
                <div className="rounded-2xl border border-[var(--accent-cyan)]/30 bg-[var(--card-bg)] p-8 text-center shadow-[var(--shadow-lg)]">
                  <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30 mb-4">
                    <Radar className="h-7 w-7 animate-spin" />
                  </div>
                  <h3 className="text-lg font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                    Deconstructing Threat Vectors...
                  </h3>
                  <p className="mt-1 text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-md mx-auto">
                    Analyzing linguistic urgency, domain reputation, social engineering patterns, and coercive cues.
                  </p>
                  <div className="mt-5 flex justify-center items-center gap-2 text-[11px] text-[var(--accent-cyan)] font-mono">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-[var(--accent-cyan)] animate-ping" />
                    <span>Aegis AI is examining this submission...</span>
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
          <div className="p-8 text-center text-[var(--muted-foreground)]">Loading threat analyzer...</div>
        </AppShell>
      }
    >
      <AnalyzePageContent />
    </Suspense>
  );
}
