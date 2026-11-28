'use client';

import React, { useState, useRef, useEffect } from 'react';
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
import Link from 'next/link';
import { useQuota } from '@/hooks/use-quota';
import { isCapabilityExhausted, createAttemptIdempotencyKey } from '@/lib/quota-types';

const MAX_CHARACTERS = 5000;
const ANALYZE_TIMEOUT_MS = 56000;

interface MessageAnalyzerProps {
  onAnalysisComplete: (result: ScamAnalysisResult) => void;
  onAnalysisStart?: () => void;
  onClear?: () => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  prefilledText?: string | null;
}

export default function MessageAnalyzer({
  onAnalysisComplete,
  onAnalysisStart,
  onClear,
  isLoading,
  setIsLoading,
  prefilledText,
}: MessageAnalyzerProps) {
  const { quota, updateQuotaSnapshot, refreshQuota } = useQuota();
  const [message, setMessage] = useState(prefilledText || '');
  const [activeExampleId, setActiveExampleId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorCategory, setErrorCategory] = useState<
    | 'general'
    | 'timeout'
    | 'rate_limiter_unavailable'
    | 'rate_limit_exceeded'
    | 'quota_exhausted'
    | 'email_verification_required'
  >('general');
  const [redactedCount, setRedactedCount] = useState<number | null>(null);
  const inFlightRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef(true);
  const isQuotaBlocked = isCapabilityExhausted(quota, 'message_analysis');

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
      inFlightRef.current = false;
    };
  }, []);

  const [prevPrefilledText, setPrevPrefilledText] = useState(prefilledText);

  // Sync external prefilled scenario selection during render when prop changes
  if (prefilledText !== prevPrefilledText) {
    setPrevPrefilledText(prefilledText);
    if (prefilledText && prefilledText.length > 0) {
      setMessage(prefilledText);
      setError(null);
      setErrorCategory('general');
      setRedactedCount(null);
      setActiveExampleId(null);
    }
  }

  const characterCount = message.length;
  const isOverLimit = characterCount > MAX_CHARACTERS;

  const handleSelectExample = (example: ExampleMessage) => {
    setMessage(example.text);
    setActiveExampleId(example.id);
    setError(null);
    setErrorCategory('general');
    setRedactedCount(null);
  };

  const handleClear = () => {
    setMessage('');
    setActiveExampleId(null);
    setError(null);
    setErrorCategory('general');
    setRedactedCount(null);
    onClear?.();
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
    if (inFlightRef.current || isLoading || isQuotaBlocked) return;

    const trimmed = message.trim();

    if (!trimmed) {
      setError('Please paste or type a message to analyze.');
      setErrorCategory('general');
      return;
    }

    if (trimmed.length > MAX_CHARACTERS) {
      setError(
        `Message exceeds the limit of ${MAX_CHARACTERS.toLocaleString()} characters (${trimmed.length.toLocaleString()} characters). Please shorten the text.`
      );
      setErrorCategory('general');
      return;
    }

    inFlightRef.current = true;
    onAnalysisStart?.();
    setError(null);
    setErrorCategory('general');
    setIsLoading(true);

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = controller;
    let didClientTimeout = false;
    const timeoutId = controller
      ? window.setTimeout(() => {
          didClientTimeout = true;
          controller.abort();
        }, ANALYZE_TIMEOUT_MS)
      : undefined;

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-aegis-idempotency-key': createAttemptIdempotencyKey(),
        },
        credentials: 'same-origin',
        body: JSON.stringify({ message: trimmed }),
        signal: controller?.signal,
      });

      const contentType = response.headers.get('content-type') || '';
      const rawText = await response.text().catch(() => '');
      let data: any = null;

      if (rawText) {
        if (rawText.includes('<!DOCTYPE') || rawText.includes('<html')) {
          setError(
            response.status === 502 || response.status === 504 || response.status === 500
              ? `Server gateway error (HTTP ${response.status}). The AI analysis service is temporarily restarting or timing out. Please retry in a moment.`
              : `Server returned an HTML response (HTTP ${response.status}). Please check your connection or retry.`
          );
          if (response.status === 504) {
            setErrorCategory('timeout');
          }
          return;
        }

        try {
          data = JSON.parse(rawText);
        } catch {
          if (!contentType.includes('application/json')) {
            data = { error: rawText.trim() || `Analysis request failed with status ${response.status}.` };
          }
        }
      }

      if (data?.quota) {
        updateQuotaSnapshot(data.quota);
      } else if (response.status !== 400) {
        refreshQuota();
      }

      if (!response.ok || data?.error) {
        if (data?.errorCode === 'quota_exhausted' || data?.errorCode === 'invalid_guest_token') {
          setErrorCategory('quota_exhausted');
        } else if (data?.errorCode === 'email_verification_required') {
          setErrorCategory('email_verification_required');
        } else if (response.status === 504) {
          setErrorCategory('timeout');
        } else if (data?.errorCode === 'rate_limiter_unavailable') {
          setErrorCategory('rate_limiter_unavailable');
        } else if (data?.errorCode === 'rate_limit_exceeded' || response.status === 429) {
          setErrorCategory('rate_limit_exceeded');
        }
        const errorMsg =
          data?.error ||
          (response.status === 502 || response.status === 504
            ? `Analysis request timed out or encountered a gateway error (HTTP ${response.status}). Please retry in a moment.`
            : `Analysis request failed (HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ''}).`);
        setError(errorMsg);
        return;
      }

      if (
        !data ||
        typeof data !== 'object' ||
        typeof data.riskLevel !== 'string' ||
        typeof data.summary !== 'string'
      ) {
        setError('Analysis response was empty or incomplete. Please retry in a moment.');
        return;
      }

      setError(null);
      setErrorCategory('general');
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
      if (!isMountedRef.current) return;
      const isAbort =
        didClientTimeout ||
        (err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError'));
      if (isAbort) {
        setErrorCategory('timeout');
        setError('Analysis timed out awaiting a response. No quota credit was consumed — please retry.');
      } else {
        const msg = err instanceof Error ? err.message : 'An unexpected error occurred during analysis.';
        setError(msg);
      }
    } finally {
      if (timeoutId !== undefined) {
        window.clearTimeout(timeoutId);
      }
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
      inFlightRef.current = false;
      if (isMountedRef.current) {
        setIsLoading(false);
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!inFlightRef.current && !isLoading && !isOverLimit && !isQuotaBlocked && message.trim().length > 0) {
        handleAnalyze();
      }
    }
  };

  return (
    <section id="analyzer" aria-label="Message Analyzer" className="relative mx-auto max-w-5xl">
      <div className="relative rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-8 shadow-[var(--shadow-md)]">
        {/* Card Header */}
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[var(--border-subtle)] pb-4">
          <div>
            <h2 className="text-lg sm:text-xl font-bold tracking-tight text-[var(--foreground)] flex items-center gap-2 font-[family-name:var(--font-display)]">
              <ShieldAlert className="h-5 w-5 text-[var(--primary-orange)]" />
              <span>Threat Intelligence Analyzer</span>
            </h2>
            <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] mt-0.5">
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
                  className="min-h-[36px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-xs font-medium text-[var(--accent-cyan)] hover:border-[var(--accent-cyan)]/50 transition-colors focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
                >
                  <EyeOff className="h-3.5 w-3.5" />
                  <span>Mask PII</span>
                </button>

                <button
                  onClick={handleClear}
                  type="button"
                  className="min-h-[36px] inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-interactive)] px-2.5 py-1 text-xs font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none cursor-pointer"
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
          <div className="mb-2 flex items-center justify-between text-xs text-[var(--foreground-secondary)] font-medium">
            <span>Or test with benchmark attack vectors:</span>
            <span className="hidden sm:inline text-[var(--muted-foreground)]">Click to populate</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            {SAMPLE_MESSAGES.map((example) => {
              const isSelected = activeExampleId === example.id;
              return (
                <button
                  key={example.id}
                  type="button"
                  onClick={() => handleSelectExample(example)}
                  className={`group relative text-left rounded-xl p-3 border transition-all duration-200 cursor-pointer min-h-[64px] focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none ${
                    isSelected
                      ? 'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)] text-[var(--foreground)] ring-1 ring-[var(--primary-orange)]/40'
                      : 'border-[var(--border)] bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)]/40 text-[var(--foreground-secondary)]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-cyan)] font-mono">
                      {example.category}
                    </span>
                    <ArrowRight className="h-3 w-3 text-[var(--muted-foreground)] group-hover:text-[var(--primary-orange)] transition-colors" />
                  </div>
                  <p className="mt-1 text-xs font-semibold text-[var(--foreground)] line-clamp-1">
                    {example.title}
                  </p>
                </button>
              );
            })}
          </div>

          {/* Quick Safe Message Baseline */}
          <div className="mt-2.5 flex items-center justify-between text-[11px] text-[var(--foreground-secondary)]">
            {redactedCount !== null && (
              <span className="text-[var(--accent-cyan)] font-mono">
                Masked {redactedCount} sensitive item{redactedCount === 1 ? '' : 's'}.
              </span>
            )}
            <button
              type="button"
              onClick={() => handleSelectExample(SAFE_SAMPLE_MESSAGE)}
              className="ml-auto text-[var(--foreground-secondary)] hover:text-[var(--status-success)] transition-colors inline-flex items-center gap-1 cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none rounded"
            >
              <CheckCircle className="h-3 w-3 text-[var(--status-success)]" />
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
            className={`w-full resize-y rounded-xl border bg-[var(--surface-interactive)] px-4 py-3.5 text-sm text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none transition-all font-mono sm:font-sans ${
              isOverLimit
                ? 'border-[var(--status-critical)] focus:ring-2 focus:ring-[var(--status-critical)]/25'
                : 'border-[var(--border)] focus:border-[var(--accent-cyan)] focus:ring-2 focus:ring-[var(--accent-cyan)]/20'
            }`}
          />

          {/* Textarea Bottom Bar */}
          <div className="mt-1.5 flex items-center justify-between text-xs px-1">
            <span
              className={`flex items-center gap-1 font-mono tabular-nums ${
                isOverLimit
                  ? 'text-[var(--status-critical)] font-semibold'
                  : characterCount > 4000
                  ? 'text-[var(--status-warning)]'
                  : 'text-[var(--muted-foreground)]'
              }`}
            >
              <span>{characterCount.toLocaleString()}</span> / {MAX_CHARACTERS.toLocaleString()} characters
            </span>
            <span className="hidden sm:inline text-[var(--muted-foreground)] text-[11px]">
              Press <kbd className="rounded border border-[var(--border)] bg-[var(--surface-interactive)] px-1 py-0.5 font-mono text-[10px]">Ctrl</kbd> + <kbd className="rounded border border-[var(--border)] bg-[var(--surface-interactive)] px-1 py-0.5 font-mono text-[10px]">Enter</kbd> to analyze
            </span>
          </div>
        </div>

        {/* Error / Timeout Display with Instant Retry */}
        {error && (
          <div
            role="alert"
            className="mt-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-4 text-xs sm:text-sm text-[var(--status-critical)]"
          >
            <div className="flex items-start gap-2.5">
              {errorCategory === 'timeout' || errorCategory === 'rate_limit_exceeded' ? (
                <Clock className="h-5 w-5 shrink-0 text-[var(--status-warning)] mt-0.5" />
              ) : (
                <AlertCircle className="h-5 w-5 shrink-0 text-[var(--status-critical)] mt-0.5" />
              )}
              <div className="leading-relaxed">
                <strong className="font-semibold">
                  {errorCategory === 'quota_exhausted'
                    ? 'Investigation Credits Exhausted: '
                    : errorCategory === 'email_verification_required'
                    ? 'Email Verification Required: '
                    : errorCategory === 'timeout'
                    ? 'Analysis Timeout: '
                    : errorCategory === 'rate_limiter_unavailable'
                    ? 'Rate-Limit Protection Unavailable: '
                    : errorCategory === 'rate_limit_exceeded'
                    ? 'Request Quota Reached: '
                    : 'Analysis Error: '}
                </strong>
                <span>{error}</span>
              </div>
            </div>

            {errorCategory === 'quota_exhausted' && quota?.ownerType !== 'user' ? (
              <Link
                href="/auth/register"
                className="self-start sm:self-auto min-h-[36px] inline-flex items-center gap-1.5 rounded-lg bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] transition-colors shrink-0"
              >
                <span>Create Free Account</span>
              </Link>
            ) : errorCategory !== 'quota_exhausted' && errorCategory !== 'email_verification_required' ? (
              <button
                type="button"
                onClick={handleAnalyze}
                disabled={isLoading}
                className="self-start sm:self-auto min-h-[36px] inline-flex items-center gap-1.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-interactive)] border border-[var(--status-critical-border)] px-3 py-1.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Retry Analysis</span>
              </button>
            ) : null}
          </div>
        )}

        {/* Action Button & Zero Retention Notice */}
        <div className="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-t border-[var(--border-subtle)] pt-5">
          <div className="flex items-start gap-2 max-w-md text-xs text-[var(--foreground-secondary)]">
            <Lock className="h-4 w-4 shrink-0 text-[var(--accent-cyan)] mt-0.5" />
            <p className="leading-snug">
              <strong className="font-semibold text-[var(--foreground)]">Zero-Retention Policy:</strong> Messages are processed in memory strictly for threat analysis and never persisted or shared.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isLoading || message.trim().length === 0 || isOverLimit || isQuotaBlocked}
              className={`w-full sm:w-auto min-h-[44px] inline-flex items-center justify-center gap-2.5 rounded-xl px-6 py-3 text-sm font-semibold shadow-md transition-all duration-200 cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none ${
                isLoading || message.trim().length === 0 || isOverLimit || isQuotaBlocked
                  ? 'bg-[var(--primary-orange)]/40 text-[var(--primary-foreground)] opacity-60 cursor-not-allowed'
                  : 'bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] active:scale-[0.98] shadow-[var(--primary-orange-glow)]'
              }`}
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Evaluating Threat Vectors...</span>
                </>
              ) : isQuotaBlocked ? (
                <>
                  <Lock className="h-4 w-4" />
                  <span>Credits Exhausted</span>
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4" />
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
