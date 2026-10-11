'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  Shield,
  AlertCircle,
  RotateCcw,
  Info,
  Loader2,
  ArrowRight,
  CheckCircle,
  EyeOff,
  Lock,
  RefreshCw,
  Clock,
} from 'lucide-react';
import {
  SAMPLE_MESSAGES,
  SAFE_SAMPLE_MESSAGE,
  ScamAnalysisResult,
  ExampleMessage,
} from '@/lib/scam-analyzer';

const MAX_CHARACTERS = 5000;

interface MessageAnalyzerProps {
  onAnalysisComplete: (result: ScamAnalysisResult) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export default function MessageAnalyzer({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
}: MessageAnalyzerProps) {
  const [message, setMessage] = useState('');
  const [activeExampleId, setActiveExampleId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isTimeoutError, setIsTimeoutError] = useState(false);
  const [redactedCount, setRedactedCount] = useState<number | null>(null);

  const characterCount = message.length;
  const isOverLimit = characterCount > MAX_CHARACTERS;

  const handleSelectExample = (example: ExampleMessage) => {
    setMessage(example.text);
    setActiveExampleId(example.id);
    setError(null);
    setIsTimeoutError(false);
    setRedactedCount(null);
  };

  const handleClear = () => {
    setMessage('');
    setActiveExampleId(null);
    setError(null);
    setIsTimeoutError(false);
    setRedactedCount(null);
  };

  // Client-side PII Masking utility before sending to inference
  const handleRedactPII = () => {
    if (!message) return;
    let count = 0;

    // Redact credit cards
    let updated = message.replace(/\b(?:\d[ -]*?){13,16}\b/g, () => {
      count++;
      return '[REDACTED_CARD]';
    });

    // Redact email addresses
    updated = updated.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, () => {
      count++;
      return '[REDACTED_EMAIL]';
    });

    // Redact phone numbers
    updated = updated.replace(/(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, () => {
      count++;
      return '[REDACTED_PHONE]';
    });

    setMessage(updated);
    setRedactedCount(count);
  };

  const handleAnalyze = async () => {
    const trimmed = message.trim();

    if (!trimmed) {
      setError('Please paste or type a message to analyze.');
      setIsTimeoutError(false);
      return;
    }

    if (trimmed.length > MAX_CHARACTERS) {
      setError(
        `Message exceeds the limit of ${MAX_CHARACTERS.toLocaleString()} characters (${trimmed.length.toLocaleString()} characters). Please shorten the text.`
      );
      setIsTimeoutError(false);
      return;
    }

    setError(null);
    setIsTimeoutError(false);
    setIsLoading(true);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: trimmed }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        if (response.status === 504) {
          setIsTimeoutError(true);
        }
        const errorMsg =
          data?.error ||
          `Analysis request failed (HTTP ${response.status} ${response.statusText}).`;
        throw new Error(errorMsg);
      }

      if (!data || typeof data !== 'object') {
        throw new Error('Received an invalid or empty response format from the server.');
      }

      onAnalysisComplete(data as ScamAnalysisResult);

      // Smooth scroll to results
      setTimeout(() => {
        const resultsEl = document.getElementById('results-section');
        if (resultsEl) {
          resultsEl.scrollIntoView({ behavior: 'smooth' });
          resultsEl.focus();
        }
      }, 100);
    } catch (err: unknown) {
      console.error('Analysis failed:', err);
      const msg = err instanceof Error ? err.message : 'An unexpected error occurred during analysis.';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!isLoading && !isOverLimit && message.trim().length > 0) {
        handleAnalyze();
      }
    }
  };

  return (
    <section id="analyzer" aria-label="Message Analyzer" className="relative mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
      <div className="relative rounded-2xl border border-cyan-500/20 bg-[#0d1322]/90 p-5 sm:p-8 shadow-2xl shadow-cyan-950/40 backdrop-blur-xl">
        {/* Card Header */}
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/5 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-cyan-400" />
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-cyan-400" />
                <span>Threat Intelligence Analyzer</span>
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Paste SMS alerts, suspicious emails, corporate BEC lures, or crypto recovery solicitations for AI threat triage.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {message.length > 0 && (
              <>
                <button
                  onClick={handleRedactPII}
                  type="button"
                  title="Mask emails, phone numbers, and credit cards before submission"
                  className="min-h-[36px] inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs text-cyan-300 hover:text-cyan-200 hover:border-cyan-500/40 transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer"
                >
                  <EyeOff className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Mask PII</span>
                </button>

                <button
                  onClick={handleClear}
                  type="button"
                  className="min-h-[36px] inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs text-slate-400 hover:text-white transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Clear</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Clickable Benchmark Attack Vectors */}
        <div className="mb-4">
          <div className="mb-2 flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Or test with benchmark attack vectors:</span>
            <span className="hidden sm:inline text-slate-500">Click to populate</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            {SAMPLE_MESSAGES.map((example) => {
              const isSelected = activeExampleId === example.id;
              return (
                <button
                  key={example.id}
                  type="button"
                  onClick={() => handleSelectExample(example)}
                  className={`group relative text-left rounded-xl p-3 border transition-all duration-200 cursor-pointer min-h-[64px] focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-950/40 text-cyan-100 ring-1 ring-cyan-500/50'
                      : 'border-white/5 bg-slate-900/60 hover:border-cyan-500/30 hover:bg-slate-900/90 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-cyan-400 font-mono">
                      {example.category}
                    </span>
                    <ArrowRight className="h-3 w-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                  </div>
                  <p className="mt-1 text-xs font-medium text-slate-200 line-clamp-1">
                    {example.title}
                  </p>
                </button>
              );
            })}
          </div>

          {/* Quick Safe Message Baseline */}
          <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-400">
            {redactedCount !== null && (
              <span className="text-cyan-400 font-mono">
                Masked {redactedCount} sensitive item{redactedCount === 1 ? '' : 's'}.
              </span>
            )}
            <button
              type="button"
              onClick={() => handleSelectExample(SAFE_SAMPLE_MESSAGE)}
              className="ml-auto text-slate-400 hover:text-emerald-400 transition-colors inline-flex items-center gap-1 cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded"
            >
              <CheckCircle className="h-3 w-3 text-emerald-500" />
              <span>Test clean baseline message</span>
            </button>
          </div>
        </div>

        {/* Textarea Input */}
        <div className="relative mt-2">
          <label htmlFor="message-input" className="sr-only">
            Suspicious message content
          </label>
          <textarea
            id="message-input"
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
              if (error) setError(null);
            }}
            onKeyDown={handleKeyDown}
            rows={7}
            placeholder="Paste suspicious text here... (e.g. SMS bank fraud alerts, email invoice redirection, CEO gift card requests, delivery fee smishing)"
            className={`w-full resize-y rounded-xl border bg-[#090d18] px-4 py-3.5 text-sm text-slate-100 placeholder-slate-500 shadow-inner focus:outline-none transition-all font-mono sm:font-sans ${
              isOverLimit
                ? 'border-red-500/60 focus:ring-2 focus:ring-red-500/30'
                : 'border-white/10 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20'
            }`}
          />

          {/* Textarea Bottom Bar */}
          <div className="mt-1.5 flex items-center justify-between text-xs px-1">
            <span
              className={`flex items-center gap-1 font-mono ${
                isOverLimit
                  ? 'text-red-400 font-semibold'
                  : characterCount > 4000
                  ? 'text-amber-400'
                  : 'text-slate-400'
              }`}
            >
              <span>{characterCount.toLocaleString()}</span> / {MAX_CHARACTERS.toLocaleString()} characters
            </span>
            <span className="hidden sm:inline text-slate-500 text-[11px]">
              Press <kbd className="rounded border border-white/10 bg-white/5 px-1 py-0.5 font-mono text-[10px]">Ctrl</kbd> + <kbd className="rounded border border-white/10 bg-white/5 px-1 py-0.5 font-mono text-[10px]">Enter</kbd> to analyze
            </span>
          </div>
        </div>

        {/* Error / Timeout Display with Instant Retry */}
        {error && (
          <div
            role="alert"
            className="mt-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-lg border border-red-500/30 bg-red-950/40 p-4 text-xs sm:text-sm text-red-300"
          >
            <div className="flex items-start gap-2.5">
              {isTimeoutError ? (
                <Clock className="h-5 w-5 shrink-0 text-amber-400 mt-0.5" />
              ) : (
                <AlertCircle className="h-5 w-5 shrink-0 text-red-400 mt-0.5" />
              )}
              <div className="leading-relaxed">
                <strong className="font-semibold text-red-200">
                  {isTimeoutError ? 'Inference Timeout (25s): ' : 'Analysis Error: '}
                </strong>
                <span>{error}</span>
              </div>
            </div>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isLoading}
              className="self-start sm:self-auto min-h-[36px] inline-flex items-center gap-1.5 rounded-lg bg-red-900/60 hover:bg-red-800/80 border border-red-500/40 px-3 py-1.5 text-xs font-semibold text-white transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Retry Analysis</span>
            </button>
          </div>
        )}

        {/* Action Button & Zero Retention Notice */}
        <div className="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-t border-white/5 pt-5">
          <div className="flex items-start gap-2 max-w-md text-xs text-slate-400">
            <Lock className="h-4 w-4 shrink-0 text-cyan-400/80 mt-0.5" />
            <p className="leading-snug">
              <strong className="font-semibold text-slate-300">Zero-Retention Policy:</strong> Messages are processed in memory strictly for threat analysis and never persisted or shared.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isLoading || message.trim().length === 0 || isOverLimit}
              className={`w-full sm:w-auto min-h-[44px] inline-flex items-center justify-center gap-2.5 rounded-xl px-6 py-3 text-sm font-semibold text-white shadow-lg transition-all duration-200 cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none ${
                isLoading || message.trim().length === 0 || isOverLimit
                  ? 'bg-cyan-600/50 opacity-60 cursor-not-allowed'
                  : 'bg-cyan-600 hover:bg-cyan-500 active:scale-[0.98] shadow-cyan-600/30 hover:shadow-cyan-500/40'
              }`}
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin text-white" />
                  <span>Evaluating Threat Vectors...</span>
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 text-white" />
                  <span>Analyze Message</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
