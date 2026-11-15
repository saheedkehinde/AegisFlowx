import { redactSecrets } from '@/lib/model-config';
import { isGeminiConfigured, isGeminiFallbackEnabled, isGeminiSearchFallbackEnabled } from '@/lib/gemini/client';

export type ProviderName = 'featherless' | 'gemini' | 'serper' | 'urlhaus';

export type ProviderErrorCode =
  | 'auth_failure'
  | 'rate_limited'
  | 'quota_exhausted'
  | 'timeout'
  | 'unavailable'
  | 'bad_request'
  | 'unconfigured'
  | 'unknown';

export interface ProviderError {
  provider: ProviderName;
  code: ProviderErrorCode;
  httpStatus?: number;
  message: string;
  isRetryable: boolean;
}

export interface ProviderExecutionResult<T> {
  data: T;
  providerUsed: ProviderName;
  modelUsed: string;
  isFallback: boolean;
  attemptsCount: number;
  latencyMs: number;
  fallbackReason?: string;
}

// In-memory cooldown tracker to avoid hammering failing providers
interface CooldownEntry {
  expiresAt: number;
  reason: ProviderErrorCode;
}
const COOLDOWN_MAP = new Map<ProviderName, CooldownEntry>();

// Volatile diagnostic tracker for latest provider outcomes
interface LatestProviderState {
  lastAttemptAt?: string;
  lastProviderUsed?: ProviderName;
  lastOutcome?: 'success' | 'fallback_success' | 'failure';
  lastErrorCode?: ProviderErrorCode;
  totalPrimaryAttempts: number;
  totalFallbackAttempts: number;
}
const PROVIDER_METRICS: Record<'ai' | 'search', LatestProviderState> = {
  ai: { totalPrimaryAttempts: 0, totalFallbackAttempts: 0 },
  search: { totalPrimaryAttempts: 0, totalFallbackAttempts: 0 },
};

/**
 * Classifies an HTTP response status and body into a structured ProviderErrorCode.
 */
export function classifyHttpError(status: number, bodySnippet: string = ''): ProviderErrorCode {
  const lower = bodySnippet.toLowerCase();

  if (status === 401 || status === 403) {
    return 'auth_failure';
  }

  if (status === 429) {
    if (
      lower.includes('quota') ||
      lower.includes('credit') ||
      lower.includes('exhausted') ||
      lower.includes('exceeded') ||
      lower.includes('limit reached') ||
      lower.includes('capacity_exhausted')
    ) {
      return 'quota_exhausted';
    }
    return 'rate_limited';
  }

  if (status === 408 || status === 504 || lower.includes('timeout') || lower.includes('abort')) {
    return 'timeout';
  }

  if (status === 502 || status === 503 || status === 500) {
    return 'unavailable';
  }

  if (status >= 400 && status < 500) {
    return 'bad_request';
  }

  return 'unknown';
}

/**
 * Determines whether a classified provider error is eligible for fallback.
 * Client errors (400, auth failure on user input, etc.) are never retryable.
 * Upstream rate limits, quotas, timeouts, and outages are retryable.
 */
export function isEligibleForFallback(code: ProviderErrorCode): boolean {
  switch (code) {
    case 'rate_limited':
    case 'quota_exhausted':
    case 'timeout':
    case 'unavailable':
      return true;
    case 'auth_failure':
    case 'bad_request':
    case 'unconfigured':
    case 'unknown':
    default:
      return false;
  }
}

/**
 * Checks if a provider is currently under active temporary cooldown.
 */
export function isProviderInCooldown(provider: ProviderName): boolean {
  const entry = COOLDOWN_MAP.get(provider);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    COOLDOWN_MAP.delete(provider);
    return false;
  }
  return true;
}

/**
 * Registers temporary cooldown for an upstream failing provider (15-60s depending on code).
 */
export function registerProviderCooldown(provider: ProviderName, code: ProviderErrorCode, ttlSeconds: number = 30): void {
  COOLDOWN_MAP.set(provider, {
    expiresAt: Date.now() + ttlSeconds * 1000,
    reason: code,
  });
}

/**
 * Updates volatile runtime metrics for health diagnostics.
 */
export function recordProviderMetric(
  category: 'ai' | 'search',
  providerUsed: ProviderName,
  outcome: 'success' | 'fallback_success' | 'failure',
  errorCode?: ProviderErrorCode
): void {
  const state = PROVIDER_METRICS[category];
  state.lastAttemptAt = new Date().toISOString();
  state.lastProviderUsed = providerUsed;
  state.lastOutcome = outcome;
  state.lastErrorCode = errorCode;

  if (outcome === 'fallback_success') {
    state.totalFallbackAttempts++;
  } else {
    state.totalPrimaryAttempts++;
  }
}

/**
 * Returns safe diagnostic metrics without secrets or user content.
 */
export function getProviderTelemetry(): {
  gemini: {
    isConfigured: boolean;
    aiFallbackEnabled: boolean;
    searchFallbackEnabled: boolean;
    inCooldown: boolean;
  };
  featherless: {
    inCooldown: boolean;
  };
  serper: {
    inCooldown: boolean;
  };
  aiMetrics: LatestProviderState;
  searchMetrics: LatestProviderState;
} {
  return {
    gemini: {
      isConfigured: isGeminiConfigured(),
      aiFallbackEnabled: isGeminiFallbackEnabled(),
      searchFallbackEnabled: isGeminiSearchFallbackEnabled(),
      inCooldown: isProviderInCooldown('gemini'),
    },
    featherless: {
      inCooldown: isProviderInCooldown('featherless'),
    },
    serper: {
      inCooldown: isProviderInCooldown('serper'),
    },
    aiMetrics: { ...PROVIDER_METRICS.ai },
    searchMetrics: { ...PROVIDER_METRICS.search },
  };
}
