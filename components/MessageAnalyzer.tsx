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

  const characterCount = message.length;
  const isOverLimit = characterCount > MAX_CHARACTERS;

  const handleSelectExample = (example: ExampleMessage) => {
    setMessage(example.text);
    setActiveExampleId(example.id);
    setError(null);
  };

  const handleClear = () => {
    setMessage('');
    setActiveExampleId(null);
    setError(null);
  };

  const handleAnalyze = async () => {
    const trimmed = message.trim();

    if (!trimmed) {
      setError('Please paste or type a message to analyze.');
      return;
    }

    if (trimmed.length > MAX_CHARACTERS) {
      setError(
        `Message exceeds the limit of ${MAX_CHARACTERS.toLocaleString()} characters (${trimmed.length.toLocaleString()} characters). Please shorten the text.`
      );
      return;
    }

    setError(null);
    setIsLoading(true);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: trimmed }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
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
    <section id="analyzer" className="relative mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
      <div className="relative rounded-2xl border border-blue-500/20 bg-[#0d1322]/90 p-5 sm:p-8 shadow-2xl shadow-blue-950/40 backdrop-blur-xl">
        {/* Card Header */}
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-white/5 pb-4">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-blue-400" />
              <span>Suspicious Message Inspection</span>
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Paste SMS text, email snippets, urgent DMs, or suspicious requests for AI security inspection.
            </p>
          </div>

          {message.length > 0 && (
            <button
              onClick={handleClear}
              type="button"
              className="self-start sm:self-auto inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Clear text</span>
            </button>
          )}
        </div>

        {/* Clickable Examples Buttons */}
        <div className="mb-4">
          <div className="mb-2 flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Or test with real-world examples:</span>
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
                  className={`group relative text-left rounded-xl p-3 border transition-all duration-200 cursor-pointer ${
                    isSelected
                      ? 'border-blue-500 bg-blue-950/40 text-blue-100 ring-1 ring-blue-500/50'
                      : 'border-white/5 bg-slate-900/60 hover:border-blue-500/30 hover:bg-slate-900/90 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-blue-400">
                      {example.category}
                    </span>
                    <ArrowRight className="h-3 w-3 text-slate-500 group-hover:text-blue-400 transition-colors" />
                  </div>
                  <p className="mt-1 text-xs font-medium text-slate-200 line-clamp-1">
                    {example.title}
                  </p>
                </button>
              );
            })}
          </div>

          {/* Quick Safe Message Link */}
          <div className="mt-2 flex items-center justify-end">
            <button
              type="button"
              onClick={() => handleSelectExample(SAFE_SAMPLE_MESSAGE)}
              className="text-[11px] text-slate-400 hover:text-emerald-400 transition-colors inline-flex items-center gap-1 cursor-pointer"
            >
              <CheckCircle className="h-3 w-3 text-emerald-500" />
              <span>Want to test a clean, safe message? Try this baseline</span>
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
            rows={6}
            placeholder="Paste suspicious text here... (e.g., 'WELLS FARGO ALERT: Verify your identity within 15 minutes...', or an email demanding immediate gift cards)"
            className={`w-full resize-y rounded-xl border bg-[#090d18] px-4 py-3.5 text-sm text-slate-100 placeholder-slate-500 shadow-inner focus:outline-none transition-all font-mono sm:font-sans ${
              isOverLimit
                ? 'border-red-500/60 focus:ring-2 focus:ring-red-500/30'
                : 'border-white/10 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20'
            }`}
          />

          {/* Textarea Bottom Bar: Character count & shortcuts */}
          <div className="mt-1.5 flex items-center justify-between text-xs px-1">
            <span
              className={`flex items-center gap-1 font-mono ${
                isOverLimit ? 'text-red-400 font-semibold' : 'text-slate-400'
              }`}
            >
              <span>{characterCount.toLocaleString()}</span> / {MAX_CHARACTERS.toLocaleString()} characters
            </span>
            <span className="hidden sm:inline text-slate-500 text-[11px]">
              Press <kbd className="rounded border border-white/10 bg-white/5 px-1 py-0.5 font-mono text-[10px]">Ctrl</kbd> + <kbd className="rounded border border-white/10 bg-white/5 px-1 py-0.5 font-mono text-[10px]">Enter</kbd> to analyze
            </span>
          </div>
        </div>

        {/* Error message if any */}
        {error && (
          <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-red-500/30 bg-red-950/40 p-3.5 text-xs sm:text-sm text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <div className="flex-1 leading-relaxed">
              <strong className="font-semibold text-red-200">Analysis Error: </strong>
              {error}
            </div>
          </div>
        )}

        {/* Action Button & Privacy Notice */}
        <div className="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-t border-white/5 pt-5">
          {/* Privacy Notice */}
          <div className="flex items-start gap-2 max-w-md text-xs text-slate-400">
            <Info className="h-4 w-4 shrink-0 text-blue-400/80 mt-0.5" />
            <p className="leading-snug">
              <strong className="font-semibold text-slate-300">Privacy Notice:</strong> Please remove sensitive personal information (passwords, SSNs, credit card numbers, or real phone numbers) before submitting.
            </p>
          </div>

          {/* Primary Action Button */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isLoading || message.trim().length === 0 || isOverLimit}
              className={`w-full sm:w-auto inline-flex items-center justify-center gap-2.5 rounded-xl px-6 py-3 text-sm font-semibold text-white shadow-lg transition-all duration-200 cursor-pointer ${
                isLoading || message.trim().length === 0 || isOverLimit
                  ? 'bg-blue-600/50 opacity-60 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 active:scale-[0.98] shadow-blue-600/30 hover:shadow-blue-500/50'
              }`}
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin text-white" />
                  <span>Contacting Featherless AI...</span>
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
