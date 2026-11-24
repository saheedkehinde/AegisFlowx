import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { createClient as createSupabaseClient, type SupabaseClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';
import { redactSecrets } from '@/lib/model-config';

export type RateLimitedEndpoint =
  | 'analyze'
  | 'scan_document'
  | 'fact_check'
  | 'url_investigation';

export type RateLimitScope = 'authenticated' | 'guest';
export type RateLimitFailurePolicy = 'fail_closed' | 'degraded_local';
export type RateLimitMode =
  | 'distributed_supabase'
  | 'local_dev'
  | 'degraded_local'
  | 'fail_closed';

export interface EndpointRateLimitConfig {
  guestMax: number;
  authMax: number;
  windowSeconds: number;
}

export type RateLimitFailureReason =
  | 'missing_server_config'
  | 'missing_migration_or_rpc'
  | 'auth_or_permission_error'
  | 'schema_mismatch'
  | 'timeout'
  | 'transient_rpc_error';

export interface RateLimitCheckOutcome {
  allowed: boolean;
  status: 200 | 429 | 503;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
  resetAt: string;
  scope: RateLimitScope;
  mode: RateLimitMode;
  unavailable: boolean;
  error?: string;
  errorCode?: 'rate_limit_exceeded' | 'rate_limiter_unavailable';
  rateKey: string;
  userId: string | null;
}

export interface LocalRateLimitBucket {
  count: number;
  resetAtMs: number;
}

export interface RateLimitDependencies {
  env?: NodeJS.ProcessEnv;
  serviceClient?: SupabaseClient | null;
  getAuthenticatedUserId?: () => Promise<string | null>;
  localStore?: Map<string, LocalRateLimitBucket>;
  nowMs?: () => number;
  rpcTimeoutMs?: number;
  maxRpcAttempts?: number;
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_LIMITS: Record<RateLimitedEndpoint, EndpointRateLimitConfig> = {
  analyze: { guestMax: 12, authMax: 30, windowSeconds: 60 },
  scan_document: { guestMax: 6, authMax: 15, windowSeconds: 60 },
  fact_check: { guestMax: 10, authMax: 25, windowSeconds: 60 },
  url_investigation: { guestMax: 12, authMax: 30, windowSeconds: 60 },
};

const ENV_PREFIX_MAP: Record<RateLimitedEndpoint, string> = {
  analyze: 'ANALYZE',
  scan_document: 'SCAN_DOCUMENT',
  fact_check: 'FACT_CHECK',
  url_investigation: 'URL_INVESTIGATION',
};

const GLOBAL_LOCAL_STORE = new Map<string, LocalRateLimitBucket>();
const MAX_LOCAL_BUCKETS = 5000;
const FALLBACK_RETRY_AFTER_SECONDS = 30;
const DEFAULT_RPC_TIMEOUT_MS = 3500;
const DEFAULT_MAX_RPC_ATTEMPTS = 2; // 1 initial attempt + at most 1 bounded transient retry
const RPC_RETRY_DELAY_MS = 120;
const AUTH_LOOKUP_TIMEOUT_MS = 2500;

class RateLimitTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RateLimitTimeoutError';
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  const effectiveMs = Math.max(50, timeoutMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new RateLimitTimeoutError(`${label} timed out after ${effectiveMs}ms`));
        }, effectiveMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function classifyRpcFailure(
  error: { code?: string; status?: number; message?: string } | null | undefined,
  thrownErr?: unknown
): { reason: RateLimitFailureReason; retryable: boolean; detail: string } {
  const errObj = thrownErr instanceof Error ? thrownErr : null;
  const code = String(error?.code || '').toUpperCase();
  const status = Number(error?.status || 0);
  const rawMessage = error?.message || errObj?.message || (thrownErr ? String(thrownErr) : 'empty_rpc_response');
  const lower = rawMessage.toLowerCase();

  if (
    thrownErr instanceof RateLimitTimeoutError ||
    errObj?.name === 'TimeoutError' ||
    errObj?.name === 'AbortError' ||
    lower.includes('timed out') ||
    lower.includes('timeout') ||
    lower.includes('deadline')
  ) {
    return { reason: 'timeout', retryable: true, detail: redactSecrets(rawMessage) };
  }

  // Non-retryable configuration / migration / permission / schema failures
  if (
    code === '42P01' ||
    code === 'PGRST202' ||
    code === 'PGRST205' ||
    lower.includes('does not exist') ||
    lower.includes('could not find the function') ||
    lower.includes('could not find the table') ||
    lower.includes('schema cache')
  ) {
    return { reason: 'missing_migration_or_rpc', retryable: false, detail: redactSecrets(rawMessage) };
  }

  if (
    status === 401 ||
    status === 403 ||
    code === '42501' ||
    lower.includes('permission denied') ||
    lower.includes('invalid api key') ||
    lower.includes('unauthorized') ||
    lower.includes('jwt')
  ) {
    return { reason: 'auth_or_permission_error', retryable: false, detail: redactSecrets(rawMessage) };
  }

  if (code === '23514' || code === '22P02' || code === '42883' || code === '42703') {
    return { reason: 'schema_mismatch', retryable: false, detail: redactSecrets(rawMessage) };
  }

  // Transient transport / database availability issues (eligible for 1 bounded retry)
  return { reason: 'transient_rpc_error', retryable: true, detail: redactSecrets(rawMessage) };
}

function parseBoundedInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  if (!raw || raw.trim() === '') return fallback;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

/**
 * Returns effective per-endpoint rate limits (env-configurable within safe bounds).
 */
export function getEndpointRateLimitConfig(
  endpoint: RateLimitedEndpoint,
  env: NodeJS.ProcessEnv = process.env
): EndpointRateLimitConfig {
  const defaults = DEFAULT_LIMITS[endpoint];
  const prefix = ENV_PREFIX_MAP[endpoint];

  const windowSeconds = parseBoundedInt(
    env[`RATE_LIMIT_${prefix}_WINDOW_SECONDS`] ?? env.RATE_LIMIT_WINDOW_SECONDS,
    defaults.windowSeconds,
    10,
    3600
  );
  const guestMax = parseBoundedInt(
    env[`RATE_LIMIT_${prefix}_GUEST_MAX`],
    defaults.guestMax,
    1,
    1000
  );
  const authMax = parseBoundedInt(
    env[`RATE_LIMIT_${prefix}_AUTH_MAX`],
    defaults.authMax,
    1,
    2000
  );

  return { guestMax, authMax, windowSeconds };
}

/**
 * Normalizes and validates an IP literal string (supports IPv4, IPv4:port, bracketed IPv6).
 * Rejects arbitrary non-IP text to prevent header-spoofing bucket splits.
 */
export function normalizeValidIp(rawCandidate: string | null | undefined): string | null {
  if (!rawCandidate || typeof rawCandidate !== 'string') return null;

  let trimmed = rawCandidate.trim();
  if (!trimmed || trimmed.length > 64) return null;

  // Strip surrounding brackets on IPv6 literals: [::1]:1234 or [::1]
  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    if (closeIdx !== -1) {
      trimmed = trimmed.slice(1, closeIdx);
    }
  } else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(trimmed)) {
    // Strip trailing :port on IPv4
    trimmed = trimmed.slice(0, trimmed.lastIndexOf(':'));
  }

  // Strip IPv6 zone identifier if any
  const pctIdx = trimmed.indexOf('%');
  if (pctIdx !== -1) {
    trimmed = trimmed.slice(0, pctIdx);
  }

  if (isIP(trimmed) === 0) {
    return null;
  }

  return trimmed.toLowerCase();
}

function getHeaderCaseInsensitive(req: Request, name: string): string | null {
  if (!req || !req.headers || typeof req.headers.get !== 'function') {
    return null;
  }
  return req.headers.get(name);
}

/**
 * Resolves a hardened guest network identifier from edge-verified network headers.
 *
 * Security rules:
 * - Never trusts arbitrary headers like x-client-ip, true-client-ip, x-originating-ip, or User-Agent.
 * - Prefers runtime req.ip and Vercel's edge-overwritten x-vercel-forwarded-for.
 * - When parsing multi-hop x-forwarded-for, uses the RIGHTMOST valid IP appended by the outer
 *   ingress proxy rather than the caller-spoofable leftmost element.
 * - Falls back to a single deterministic token when no trusted IP is available so missing or
 *   malformed headers never mint unlimited guest buckets.
 */
export function extractTrustedClientNetworkId(req: Request): string {
  const reqWithIp = req as Request & { ip?: unknown };
  if (typeof reqWithIp?.ip === 'string') {
    const platformIp = normalizeValidIp(reqWithIp.ip);
    if (platformIp) return `ip:${platformIp}`;
  }

  // Edge-enforced Vercel header (stripped/overwritten by Vercel Edge Network)
  const vercelForwardedFor = getHeaderCaseInsensitive(req, 'x-vercel-forwarded-for');
  if (vercelForwardedFor) {
    const parts = vercelForwardedFor.split(',').map((p) => p.trim()).filter(Boolean);
    for (let i = parts.length - 1; i >= 0; i--) {
      const valid = normalizeValidIp(parts[i]);
      if (valid) return `ip:${valid}`;
    }
  }

  // Single edge proxy IP header (e.g. nginx / reverse proxy)
  const realIp = getHeaderCaseInsensitive(req, 'x-real-ip');
  if (realIp) {
    const valid = normalizeValidIp(realIp);
    if (valid) return `ip:${valid}`;
  }

  // Multi-hop forwarded header: rightmost entry is appended by outer proxy (leftmost is spoofable)
  const xff = getHeaderCaseInsensitive(req, 'x-forwarded-for');
  if (xff) {
    const parts = xff.split(',').map((p) => p.trim()).filter(Boolean);
    for (let i = parts.length - 1; i >= 0; i--) {
      const valid = normalizeValidIp(parts[i]);
      if (valid) return `ip:${valid}`;
    }
  }

  return 'ip:untrusted-or-loopback';
}

/**
 * Derives an opaque SHA-256 rate-limit key so raw IPs, user UUIDs, message bodies,
 * file metadata, or URLs are never persisted in public.api_rate_limits.
 */
export function deriveHashedRateKey(
  endpoint: RateLimitedEndpoint,
  scope: RateLimitScope,
  rawIdentity: string,
  env: NodeJS.ProcessEnv = process.env
): string {
  const salt =
    env.RATE_LIMIT_HASH_SALT?.trim() ||
    env.SUPABASE_SERVICE_ROLE_KEY?.trim().slice(0, 16) ||
    'aegisflow-rate-limit-v1';

  const digest = createHash('sha256')
    .update(`${salt}:${endpoint}:${scope}:${rawIdentity}`, 'utf8')
    .digest('hex');

  return `${endpoint}:${scope}:${digest}`;
}

/**
 * Creates a strictly server-only Supabase service-role client (persistSession: false)
 * with bounded request timeout for invoking public.consume_rate_limit().
 */
export function getRateLimitServiceClient(
  env: NodeJS.ProcessEnv = process.env
): SupabaseClient | null {
  if (typeof window !== 'undefined') {
    return null;
  }

  const url = env.NEXT_PUBLIC_SUPABASE_URL || env.SUPABASE_URL;
  const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

  if (
    !url ||
    !serviceRoleKey ||
    url === 'YOUR_SUPABASE_URL' ||
    serviceRoleKey === 'YOUR_SUPABASE_SERVICE_ROLE_KEY' ||
    serviceRoleKey.trim().length < 20
  ) {
    return null;
  }

  try {
    const parsedUrl = new URL(url.trim());
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      return null;
    }
  } catch {
    return null;
  }

  return createSupabaseClient(url.trim(), serviceRoleKey.trim(), {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    global: {
      fetch: (input, init) => {
        const timeoutSignal = AbortSignal.timeout(DEFAULT_RPC_TIMEOUT_MS);
        const combinedSignal = init?.signal
          ? AbortSignal.any([init.signal, timeoutSignal])
          : timeoutSignal;
        return fetch(input, { ...init, signal: combinedSignal });
      },
    },
  });
}

export function resolveRateLimitFailurePolicy(
  env: NodeJS.ProcessEnv = process.env
): RateLimitFailurePolicy {
  const raw = env.RATE_LIMIT_FAILURE_POLICY?.trim().toLowerCase();
  if (raw === 'degraded_local') {
    return 'degraded_local';
  }
  return 'fail_closed';
}

function consumeLocalBucket(
  store: Map<string, LocalRateLimitBucket>,
  rateKey: string,
  limit: number,
  windowSeconds: number,
  nowMs: number,
  scope: RateLimitScope,
  mode: 'local_dev' | 'degraded_local',
  unavailable: boolean,
  userId: string | null
): RateLimitCheckOutcome {
  // Prune expired buckets opportunistically when store grows
  if (store.size > MAX_LOCAL_BUCKETS) {
    for (const [key, entry] of store.entries()) {
      if (nowMs >= entry.resetAtMs) {
        store.delete(key);
      }
      if (store.size <= MAX_LOCAL_BUCKETS * 0.8) {
        break;
      }
    }
  }

  const windowMs = windowSeconds * 1000;
  const existing = store.get(rateKey);

  if (!existing || nowMs >= existing.resetAtMs) {
    const resetAtMs = nowMs + windowMs;
    store.set(rateKey, { count: 1, resetAtMs });
    return {
      allowed: true,
      status: 200,
      limit,
      remaining: Math.max(0, limit - 1),
      retryAfterSeconds: 0,
      resetAt: new Date(resetAtMs).toISOString(),
      scope,
      mode,
      unavailable,
      rateKey,
      userId,
    };
  }

  if (existing.count >= limit) {
    const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAtMs - nowMs) / 1000));
    return {
      allowed: false,
      status: 429,
      limit,
      remaining: 0,
      retryAfterSeconds,
      resetAt: new Date(existing.resetAtMs).toISOString(),
      scope,
      mode,
      unavailable,
      error: `Request limit reached. Please wait ${retryAfterSeconds} second(s) before submitting another request.`,
      errorCode: 'rate_limit_exceeded',
      rateKey,
      userId,
    };
  }

  existing.count += 1;
  return {
    allowed: true,
    status: 200,
    limit,
    remaining: Math.max(0, limit - existing.count),
    retryAfterSeconds: 0,
    resetAt: new Date(existing.resetAtMs).toISOString(),
    scope,
    mode,
    unavailable,
    rateKey,
    userId,
  };
}

function buildFailClosedOutcome(
  rateKey: string,
  scope: RateLimitScope,
  nowMs: number,
  userId: string | null
): RateLimitCheckOutcome {
  const resetAtMs = nowMs + FALLBACK_RETRY_AFTER_SECONDS * 1000;
  return {
    allowed: false,
    status: 503,
    limit: 0,
    remaining: 0,
    retryAfterSeconds: FALLBACK_RETRY_AFTER_SECONDS,
    resetAt: new Date(resetAtMs).toISOString(),
    scope,
    mode: 'fail_closed',
    unavailable: true,
    error:
      'Rate-limiting protection service is temporarily unavailable. Expensive analysis requests are paused to safeguard platform availability. Please retry shortly.',
    errorCode: 'rate_limiter_unavailable',
    rateKey,
    userId,
  };
}

async function resolveAuthenticatedUserIdDefault(): Promise<string | null> {
  try {
    const supabase = await createServerSupabaseClient();
    if (!supabase) return null;
    const {
      data: { user },
      error,
    } = await withTimeout(supabase.auth.getUser(), AUTH_LOOKUP_TIMEOUT_MS, 'supabase.auth.getUser');
    if (!error && user?.id) {
      return user.id;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Non-mutating administrative health probe for distributed rate-limiting readiness.
 * Checks service-role configuration and verifies `public.api_rate_limits` access.
 */
export async function probeRateLimiterHealth(
  env: NodeJS.ProcessEnv = process.env,
  serviceClientOverride?: SupabaseClient | null
): Promise<{
  status: 'operational' | 'missing_configuration' | 'missing_migration' | 'authentication_failure' | 'unavailable' | 'local_dev';
  configured: boolean;
  mode: RateLimitMode;
  failurePolicy: RateLimitFailurePolicy;
  detail: string;
}> {
  const failurePolicy = resolveRateLimitFailurePolicy(env);
  const isProduction = env.NODE_ENV === 'production';
  const client =
    serviceClientOverride !== undefined ? serviceClientOverride : getRateLimitServiceClient(env);

  if (!client) {
    return {
      status: isProduction ? 'missing_configuration' : 'local_dev',
      configured: false,
      mode: isProduction ? failurePolicy : 'local_dev',
      failurePolicy,
      detail: isProduction
        ? 'Distributed rate-limit service-role credentials (SUPABASE_SERVICE_ROLE_KEY / NEXT_PUBLIC_SUPABASE_URL) are missing or invalid.'
        : 'Running in local development mode using in-process fixed-window buckets.',
    };
  }

  try {
    const { error } = await withTimeout(
      Promise.resolve(
        client.from('api_rate_limits').select('rate_key', { head: true, count: 'exact' })
      ),
      DEFAULT_RPC_TIMEOUT_MS,
      'probeRateLimiterHealth'
    );

    if (!error) {
      return {
        status: 'operational',
        configured: true,
        mode: 'distributed_supabase',
        failurePolicy,
        detail: 'Distributed Supabase rate-limit table and service-role access verified.',
      };
    }

    const classified = classifyRpcFailure(error);
    if (classified.reason === 'missing_migration_or_rpc') {
      return {
        status: 'missing_migration',
        configured: true,
        mode: failurePolicy,
        failurePolicy,
        detail: 'Rate-limit table/RPC is missing in Supabase. Apply supabase/migrations/0005_rate_limiting.sql.',
      };
    }
    if (classified.reason === 'auth_or_permission_error') {
      return {
        status: 'authentication_failure',
        configured: true,
        mode: failurePolicy,
        failurePolicy,
        detail: 'Supabase service-role authentication or permission rejected for rate-limit storage.',
      };
    }

    return {
      status: 'unavailable',
      configured: true,
      mode: failurePolicy,
      failurePolicy,
      detail: `Distributed rate-limit storage check failed: ${classified.detail.slice(0, 120)}`,
    };
  } catch (err: unknown) {
    const classified = classifyRpcFailure(null, err);
    return {
      status: 'unavailable',
      configured: true,
      mode: failurePolicy,
      failurePolicy,
      detail: `Distributed rate-limit storage probe failed (${classified.reason}).`,
    };
  }
}

/**
 * Enforces per-endpoint API rate limiting for both authenticated users and guests.
 *
 * Architecture:
 * - Resolves verified Supabase user session first (`user.id`) with bounded timeout; falls back to edge-verified guest IP.
 * - Stores only SHA-256 hashed identifiers (zero raw IPs, user UUIDs, messages, files, or URLs).
 * - Uses atomic PostgreSQL RPC `consume_rate_limit` via Supabase service-role across Vercel instances
 *   with a 3.5s per-attempt timeout and at most 1 bounded retry on transient errors (zero retry loops on config/schema errors).
 * - Never silently bypasses limits if the distributed limiter is unavailable:
 *   - Production / runtime RPC errors default to `fail_closed` (HTTP 503 + Retry-After) unless
 *     `RATE_LIMIT_FAILURE_POLICY=degraded_local` is explicitly configured (strict halved local cap).
 *   - Unconfigured local dev (`NODE_ENV !== 'production'`) uses `local_dev` fixed-window enforcement
 *     unless `RATE_LIMIT_FAILURE_POLICY=fail_closed` is set.
 */
export async function enforceApiRateLimit(
  req: Request,
  endpoint: RateLimitedEndpoint,
  deps: RateLimitDependencies = {}
): Promise<RateLimitCheckOutcome> {
  const env = deps.env || process.env;
  const nowMs = deps.nowMs ? deps.nowMs() : Date.now();
  const localStore = deps.localStore || GLOBAL_LOCAL_STORE;
  const config = getEndpointRateLimitConfig(endpoint, env);
  const rpcTimeoutMs = Math.max(100, deps.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS);
  const maxRpcAttempts = Math.max(1, Math.min(3, deps.maxRpcAttempts ?? DEFAULT_MAX_RPC_ATTEMPTS));
  const sleepFn = deps.sleep || defaultSleep;

  const getUserIdFn = deps.getAuthenticatedUserId || resolveAuthenticatedUserIdDefault;
  const userId = await getUserIdFn();

  const scope: RateLimitScope = userId ? 'authenticated' : 'guest';
  const limit = scope === 'authenticated' ? config.authMax : config.guestMax;
  const rawIdentity = userId ? `user:${userId}` : extractTrustedClientNetworkId(req);
  const rateKey = deriveHashedRateKey(endpoint, scope, rawIdentity, env);

  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getRateLimitServiceClient(env);

  const failurePolicy = resolveRateLimitFailurePolicy(env);
  const explicitFailClosed = env.RATE_LIMIT_FAILURE_POLICY?.trim().toLowerCase() === 'fail_closed';
  const isProduction = env.NODE_ENV === 'production';

  // 1. Distributed Supabase RPC path (production-grade, cross-instance atomic with timeout + bounded transient retry)
  if (serviceClient) {
    let lastFailureReason: RateLimitFailureReason = 'transient_rpc_error';
    let lastFailureDetail = 'empty_rpc_response';

    for (let attempt = 1; attempt <= maxRpcAttempts; attempt++) {
      try {
        const { data, error } = await withTimeout(
          Promise.resolve(
            serviceClient.rpc('consume_rate_limit', {
              p_rate_key: rateKey,
              p_endpoint: endpoint,
              p_scope: scope,
              p_max_requests: limit,
              p_window_seconds: config.windowSeconds,
            })
          ),
          rpcTimeoutMs,
          `consume_rate_limit(${endpoint})`
        );

        const row = Array.isArray(data) ? data[0] : data;

        if (!error && row && typeof row.allowed === 'boolean') {
          const retryAfterSeconds = Math.max(0, Number(row.retry_after_seconds ?? 0));
          const remaining = Math.max(0, Number(row.remaining ?? 0));
          const resetAt =
            typeof row.reset_at === 'string' && row.reset_at
              ? row.reset_at
              : new Date(nowMs + config.windowSeconds * 1000).toISOString();

          if (!row.allowed) {
            const safeRetry = Math.max(1, retryAfterSeconds);
            return {
              allowed: false,
              status: 429,
              limit,
              remaining: 0,
              retryAfterSeconds: safeRetry,
              resetAt,
              scope,
              mode: 'distributed_supabase',
              unavailable: false,
              error: `Request limit reached. Please wait ${safeRetry} second(s) before submitting another request.`,
              errorCode: 'rate_limit_exceeded',
              rateKey,
              userId,
            };
          }

          return {
            allowed: true,
            status: 200,
            limit,
            remaining,
            retryAfterSeconds: 0,
            resetAt,
            scope,
            mode: 'distributed_supabase',
            unavailable: false,
            rateKey,
            userId,
          };
        }

        const classified = classifyRpcFailure(error);
        lastFailureReason = classified.reason;
        lastFailureDetail = classified.detail;

        if (!classified.retryable || attempt >= maxRpcAttempts) {
          break;
        }
      } catch (rpcErr: unknown) {
        const classified = classifyRpcFailure(null, rpcErr);
        lastFailureReason = classified.reason;
        lastFailureDetail = classified.detail;

        if (!classified.retryable || attempt >= maxRpcAttempts) {
          break;
        }
      }

      // Brief bounded backoff before single transient retry
      await sleepFn(RPC_RETRY_DELAY_MS);
    }

    console.warn(
      `Distributed rate-limit RPC unavailable for ${endpoint} [${lastFailureReason}]:`,
      redactSecrets(lastFailureDetail)
    );

    // Distributed backend was configured but failed at runtime -> apply safe failure policy (never bypass)
    if (failurePolicy === 'degraded_local') {
      const degradedCap = Math.max(1, Math.floor(limit / 2));
      return consumeLocalBucket(
        localStore,
        `degraded:${rateKey}`,
        degradedCap,
        config.windowSeconds,
        nowMs,
        scope,
        'degraded_local',
        true,
        userId
      );
    }

    return buildFailClosedOutcome(rateKey, scope, nowMs, userId);
  }

  // 2. Distributed client is unconfigured
  if (isProduction) {
    console.warn(
      `Distributed rate-limit protection unconfigured in production for ${endpoint} [missing_server_config]: NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY unavailable.`
    );
    if (failurePolicy === 'degraded_local') {
      const degradedCap = Math.max(1, Math.floor(limit / 2));
      return consumeLocalBucket(
        localStore,
        `degraded:${rateKey}`,
        degradedCap,
        config.windowSeconds,
        nowMs,
        scope,
        'degraded_local',
        true,
        userId
      );
    }
    return buildFailClosedOutcome(rateKey, scope, nowMs, userId);
  }

  // Non-production local dev/test
  if (explicitFailClosed) {
    return buildFailClosedOutcome(rateKey, scope, nowMs, userId);
  }

  return consumeLocalBucket(
    localStore,
    rateKey,
    limit,
    config.windowSeconds,
    nowMs,
    scope,
    'local_dev',
    false,
    userId
  );
}

/**
 * Formats a sanitized HTTP 429 or HTTP 503 response with Retry-After and X-RateLimit headers.
 * Never exposes internal IP addresses, raw user UUIDs, API keys, or request content.
 */
export function buildRateLimitErrorResponse(outcome: RateLimitCheckOutcome): NextResponse {
  const retryAfter = Math.max(1, outcome.retryAfterSeconds || FALLBACK_RETRY_AFTER_SECONDS);
  const resetEpochSeconds = Math.max(
    1,
    Math.ceil((Date.parse(outcome.resetAt) || Date.now() + retryAfter * 1000) / 1000)
  );

  const headers: Record<string, string> = {
    'Retry-After': String(retryAfter),
    'X-RateLimit-Limit': String(outcome.limit),
    'X-RateLimit-Remaining': String(outcome.remaining),
    'X-RateLimit-Reset': String(resetEpochSeconds),
    'X-RateLimit-Scope': outcome.scope === 'authenticated' ? 'user' : 'guest',
    'X-RateLimit-Mode': outcome.mode,
  };

  const fallbackMsg =
    outcome.status === 503
      ? 'Rate-limiting protection service is temporarily unavailable. Please retry shortly.'
      : `Request limit reached. Please wait ${retryAfter} second(s) before submitting another request.`;

  return NextResponse.json(
    {
      error: redactSecrets(outcome.error || fallbackMsg),
      errorCode:
        outcome.errorCode ||
        (outcome.status === 503 ? 'rate_limiter_unavailable' : 'rate_limit_exceeded'),
      retryAfterSeconds: retryAfter,
    },
    {
      status: outcome.status === 503 ? 503 : 429,
      headers,
    }
  );
}

/**
 * Attaches non-sensitive rate-limit metadata headers onto allowed API responses.
 */
export function attachRateLimitHeaders(
  response: NextResponse,
  outcome: RateLimitCheckOutcome
): NextResponse {
  try {
    if (response?.headers && typeof response.headers.set === 'function') {
      const resetEpochSeconds = Math.max(
        1,
        Math.ceil((Date.parse(outcome.resetAt) || Date.now() + 60000) / 1000)
      );
      response.headers.set('X-RateLimit-Limit', String(outcome.limit));
      response.headers.set('X-RateLimit-Remaining', String(outcome.remaining));
      response.headers.set('X-RateLimit-Reset', String(resetEpochSeconds));
      response.headers.set('X-RateLimit-Scope', outcome.scope === 'authenticated' ? 'user' : 'guest');
      response.headers.set('X-RateLimit-Mode', outcome.mode);
    }
  } catch {
    // Non-fatal in minimal test mocks without mutable headers
  }
  return response;
}
