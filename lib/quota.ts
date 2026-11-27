import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createClient as createSupabaseClient, type SupabaseClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';
import { redactSecrets } from '@/lib/model-config';
import {
  CAPABILITY_LABELS,
  GUEST_INITIAL_SHARED_CREDITS,
  USER_INITIAL_CAPABILITY_CREDITS,
  type QuotaBalancesByCapability,
  type QuotaCapability,
  type QuotaErrorCode,
  type QuotaSnapshot,
} from '@/lib/quota-types';

export type {
  QuotaBalancesByCapability,
  QuotaCapability,
  QuotaErrorCode,
  QuotaSnapshot,
} from '@/lib/quota-types';

export const GUEST_COOKIE_NAME = 'aegis_guest_token';
export const GUEST_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365; // 1 year

const RPC_TIMEOUT_MS = 4500;
const AUTH_TIMEOUT_MS = 3000;
const RPC_RETRY_DELAY_MS = 120;
const MAX_RPC_ATTEMPTS = 2;
const GLOBAL_STORE_KEY = Symbol.for('aegisflow.localQuotaStore');
const GLOBAL_DEV_SECRET_KEY = Symbol.for('aegisflow.devGuestSecret');
const GLOBAL_DEV_MIGRATION_WARN_KEY = Symbol.for('aegisflow.devQuotaMigrationWarned');
const GLOBAL_SERVICE_CLIENTS_KEY = Symbol.for('aegisflow.quotaServiceClients');

function getDevEphemeralSigningSecret(): Buffer {
  const g = globalThis as unknown as Record<symbol, unknown>;
  if (!(g[GLOBAL_DEV_SECRET_KEY] instanceof Buffer)) {
    g[GLOBAL_DEV_SECRET_KEY] = randomBytes(32);
  }
  return g[GLOBAL_DEV_SECRET_KEY] as Buffer;
}

export interface ResolvedQuotaUser {
  status: 'guest' | 'verified' | 'unverified';
  userId: string | null;
}

export interface QuotaReservationHandle {
  reservationId: string;
  accountKey: string;
  bucket: string;
  capability: QuotaCapability;
  ownerType: 'guest' | 'user';
  mode: 'distributed_supabase' | 'local_dev';
  snapshot: QuotaSnapshot;
  cookieToSet?: {
    name: string;
    value: string;
    isHttps: boolean;
  };
}

export interface QuotaCheckOutcome {
  allowed: boolean;
  status: 200 | 403 | 503;
  error?: string;
  errorCode?: QuotaErrorCode;
  capability: QuotaCapability;
  requiresRegistration?: boolean;
  requiresVerification?: boolean;
  snapshot?: QuotaSnapshot;
  reservation?: QuotaReservationHandle;
  cookieToSet?: {
    name: string;
    value: string;
    isHttps: boolean;
  };
}

export interface QuotaSnapshotOutcome {
  ok: boolean;
  status: 200 | 403 | 503;
  snapshot?: QuotaSnapshot;
  error?: string;
  errorCode?: QuotaErrorCode;
  requiresVerification?: boolean;
  cookieToSet?: {
    name: string;
    value: string;
    isHttps: boolean;
  };
}

export interface LocalGuestRecord {
  guestHash: string;
  rotatedFromHash?: string;
  supersededByHash?: string;
  claimedByUserId?: string;
  claimedAt?: string;
  accountKey: string;
  balance: number;
  initialGrantIssued: boolean;
}

export interface LocalUserRecord {
  userId: string;
  accountKey: string;
  initialGrantIssued: boolean;
  claimedGuestHash?: string;
  balances: QuotaBalancesByCapability;
}

export interface LocalReservationRecord {
  id: string;
  accountKey: string;
  ownerType: 'guest' | 'user';
  bucket: string;
  capability: QuotaCapability;
  status: 'reserved' | 'committed' | 'refunded';
  idempotencyKey?: string;
  failureReason?: string;
  createdAtMs?: number;
}

export interface LocalQuotaStore {
  guests: Map<string, LocalGuestRecord>;
  users: Map<string, LocalUserRecord>;
  reservations: Map<string, LocalReservationRecord>;
  idempotency: Map<string, string>;
}

export function createLocalQuotaStore(): LocalQuotaStore {
  return {
    guests: new Map(),
    users: new Map(),
    reservations: new Map(),
    idempotency: new Map(),
  };
}

function getGlobalLocalQuotaStore(): LocalQuotaStore {
  const g = globalThis as unknown as Record<symbol, unknown>;
  if (!g[GLOBAL_STORE_KEY]) {
    g[GLOBAL_STORE_KEY] = createLocalQuotaStore();
  }
  return g[GLOBAL_STORE_KEY] as LocalQuotaStore;
}

export interface QuotaDependencies {
  env?: NodeJS.ProcessEnv;
  serviceClient?: SupabaseClient | null;
  resolveUser?: () => Promise<ResolvedQuotaUser>;
  localStore?: LocalQuotaStore;
  nowMs?: () => number;
}

function isProductionEnv(env: NodeJS.ProcessEnv): boolean {
  return env.NODE_ENV === 'production';
}

function isMissingQuotaMigrationError(
  error: { code?: string; message?: string } | null | undefined
): boolean {
  if (!error) return false;
  const code = String(error.code || '').toUpperCase();
  const msg = String(error.message || '').toLowerCase();
  if (code === 'PGRST202' || code === 'PGRST205' || code === '42P01' || code === '42883') {
    return true;
  }
  return (
    msg.includes('could not find the function') ||
    msg.includes('schema cache') ||
    msg.includes('does not exist')
  );
}

function noteDevMigrationFallbackOnce(context: string): void {
  const g = globalThis as unknown as Record<symbol, unknown>;
  if (g[GLOBAL_DEV_MIGRATION_WARN_KEY]) return;
  g[GLOBAL_DEV_MIGRATION_WARN_KEY] = true;
  console.info(
    `[AegisFlow Quota] Supabase migration 0006 RPC not found in non-production (${context}); using local in-memory dev quota store until 0006_usage_quotas.sql is applied.`
  );
}

function isHttpsRequest(req: Request, env: NodeJS.ProcessEnv): boolean {
  try {
    const proto = req.headers?.get?.('x-forwarded-proto');
    if (proto) {
      return proto.split(',')[0].trim().toLowerCase() === 'https';
    }
    if (typeof req.url === 'string' && req.url.startsWith('https://')) {
      return true;
    }
  } catch {
    // Ignore malformed URL on synthetic requests
  }
  return isProductionEnv(env);
}

function isValidGuestTokenSecret(raw: string | undefined): raw is string {
  if (typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (trimmed.length < 32) return false;
  const upper = trimmed.toUpperCase();
  if (
    upper.startsWith('YOUR_') ||
    upper.startsWith('MY_') ||
    upper.startsWith('REPLACE_') ||
    upper === 'CHANGE_ME' ||
    upper === 'CHANGEME' ||
    upper.includes('PLACEHOLDER')
  ) {
    return false;
  }
  if (new Set(trimmed).size < 6) {
    return false;
  }
  return true;
}

function resolveSigningKey(env: NodeJS.ProcessEnv): Buffer | null {
  if (typeof window !== 'undefined') {
    return null;
  }

  if (isValidGuestTokenSecret(env.GUEST_TOKEN_SECRET)) {
    return createHash('sha256')
      .update(`guest-hmac:${env.GUEST_TOKEN_SECRET.trim()}`, 'utf8')
      .digest();
  }

  // Production strictly requires a valid dedicated GUEST_TOKEN_SECRET and must fail closed without it.
  if (isProductionEnv(env)) {
    return null;
  }

  const salt = env.RATE_LIMIT_HASH_SALT?.trim();
  const serviceKey = env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  if (serviceKey && serviceKey.length >= 20 && serviceKey !== 'YOUR_SUPABASE_SERVICE_ROLE_KEY') {
    return createHash('sha256')
      .update(`aegisflow-guest-hmac-v1:${salt || ''}:${serviceKey}`, 'utf8')
      .digest();
  }

  if (salt && salt.length >= 16) {
    return createHash('sha256').update(`aegisflow-guest-hmac-salt:${salt}`, 'utf8').digest();
  }

  return getDevEphemeralSigningSecret();
}

export function hashGuestTokenId(tokenId: string, env: NodeJS.ProcessEnv = process.env): string {
  const pepper =
    env.GUEST_TOKEN_HASH_PEPPER?.trim() ||
    env.RATE_LIMIT_HASH_SALT?.trim() ||
    env.SUPABASE_SERVICE_ROLE_KEY?.trim().slice(0, 16) ||
    'aegisflow-guest-hash-v1';

  return createHash('sha256').update(`guest:${pepper}:${tokenId}`, 'utf8').digest('hex');
}

export function mintSignedGuestToken(env: NodeJS.ProcessEnv = process.env): {
  cookieValue: string;
  tokenId: string;
  guestHash: string;
} | null {
  const signingKey = resolveSigningKey(env);
  if (!signingKey) return null;

  const tokenId = randomBytes(24).toString('base64url');
  const signature = createHmac('sha256', signingKey).update(tokenId, 'utf8').digest('base64url');
  return {
    cookieValue: `${tokenId}.${signature}`,
    tokenId,
    guestHash: hashGuestTokenId(tokenId, env),
  };
}

export function verifySignedGuestToken(
  rawCookieValue: string,
  env: NodeJS.ProcessEnv = process.env
): { valid: true; tokenId: string; guestHash: string } | { valid: false; reason: 'malformed' | 'forged' | 'unconfigured' } {
  if (typeof rawCookieValue !== 'string' || !rawCookieValue || rawCookieValue.length > 256) {
    return { valid: false, reason: 'malformed' };
  }

  const trimmed = rawCookieValue.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'malformed' };
  }

  const [tokenId, providedSig] = parts;
  if (!/^[A-Za-z0-9_-]{24,64}$/.test(tokenId) || !/^[A-Za-z0-9_-]{32,64}$/.test(providedSig)) {
    return { valid: false, reason: 'malformed' };
  }

  const signingKey = resolveSigningKey(env);
  if (!signingKey) {
    return { valid: false, reason: 'unconfigured' };
  }

  const expectedSig = createHmac('sha256', signingKey).update(tokenId, 'utf8').digest('base64url');
  const providedBuf = Buffer.from(providedSig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');

  if (providedBuf.length !== expectedBuf.length || !timingSafeEqual(providedBuf, expectedBuf)) {
    return { valid: false, reason: 'forged' };
  }

  return {
    valid: true,
    tokenId,
    guestHash: hashGuestTokenId(tokenId, env),
  };
}

export function extractGuestCookieValue(req: Request): string | null {
  try {
    const reqAny = req as Request & {
      cookies?: { get?: (name: string) => { value?: string } | undefined };
    };
    const nextCookieVal = reqAny?.cookies?.get?.(GUEST_COOKIE_NAME)?.value;
    if (typeof nextCookieVal === 'string' && nextCookieVal.length > 0) {
      return nextCookieVal;
    }

    const cookieHeader = req.headers?.get?.('cookie');
    if (!cookieHeader) return null;

    const pairs = cookieHeader.split(';');
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) continue;
      const key = pair.slice(0, eqIdx).trim();
      if (key === GUEST_COOKIE_NAME) {
        const rawVal = pair.slice(eqIdx + 1).trim();
        if (!rawVal) return '';
        try {
          return decodeURIComponent(rawVal);
        } catch {
          return rawVal;
        }
      }
    }
  } catch {
    return null;
  }
  return null;
}

export function buildGuestCookieHeader(
  cookieName: string,
  cookieValue: string,
  isHttps: boolean
): string {
  const parts = [
    `${cookieName}=${encodeURIComponent(cookieValue)}`,
    'Path=/',
    `Max-Age=${GUEST_COOKIE_MAX_AGE_SECONDS}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (isHttps) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

export function attachGuestCookie(
  response: NextResponse,
  cookieToSet?: { name: string; value: string; isHttps: boolean }
): NextResponse {
  if (!cookieToSet) return response;
  try {
    const resAny = response as NextResponse & {
      cookies?: {
        set?: (name: string, value: string, options: Record<string, unknown>) => void;
      };
    };
    if (resAny?.cookies && typeof resAny.cookies.set === 'function') {
      resAny.cookies.set(cookieToSet.name, cookieToSet.value, {
        httpOnly: true,
        sameSite: 'lax',
        secure: cookieToSet.isHttps,
        path: '/',
        maxAge: GUEST_COOKIE_MAX_AGE_SECONDS,
      });
      return response;
    }
    if (response?.headers && typeof response.headers.set === 'function') {
      response.headers.set(
        'Set-Cookie',
        buildGuestCookieHeader(cookieToSet.name, cookieToSet.value, cookieToSet.isHttps)
      );
    }
  } catch {
    // Non-fatal in minimal test mocks
  }
  return response;
}

function getServiceClientCache(): Map<string, SupabaseClient> {
  const g = globalThis as unknown as Record<symbol, unknown>;
  if (!(g[GLOBAL_SERVICE_CLIENTS_KEY] instanceof Map)) {
    g[GLOBAL_SERVICE_CLIENTS_KEY] = new Map<string, SupabaseClient>();
  }
  return g[GLOBAL_SERVICE_CLIENTS_KEY] as Map<string, SupabaseClient>;
}

export function getQuotaServiceClient(env: NodeJS.ProcessEnv = process.env): SupabaseClient | null {
  if (typeof window !== 'undefined') return null;

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

  const trimmedUrl = url.trim();
  const trimmedKey = serviceRoleKey.trim();

  try {
    const parsedUrl = new URL(trimmedUrl);
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      return null;
    }
  } catch {
    return null;
  }

  const cacheKey = `${trimmedUrl}:${createHash('sha256').update(trimmedKey, 'utf8').digest('hex').slice(0, 16)}`;
  const clientCache = getServiceClientCache();
  const cached = clientCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const client = createSupabaseClient(trimmedUrl, trimmedKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    global: {
      fetch: (input, init) => {
        const timeoutSignal = AbortSignal.timeout(RPC_TIMEOUT_MS);
        const combinedSignal = init?.signal
          ? AbortSignal.any([init.signal, timeoutSignal])
          : timeoutSignal;
        return fetch(input, { ...init, signal: combinedSignal });
      },
    },
  });

  if (clientCache.size < 8) {
    clientCache.set(cacheKey, client);
  }
  return client;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), Math.max(50, timeoutMs));
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function isRetryableQuotaRpcFailure(
  error: { code?: string; message?: string; status?: number } | null | undefined,
  thrownErr?: unknown
): boolean {
  if (isMissingQuotaMigrationError(error)) {
    return false;
  }

  const code = String(error?.code || '').toUpperCase();
  const status = Number(error?.status || 0);
  const msg = String(
    error?.message || (thrownErr instanceof Error ? thrownErr.message : thrownErr || '')
  ).toLowerCase();

  // Never retry auth / permission / malformed argument errors
  if (
    status === 401 ||
    status === 403 ||
    status === 400 ||
    code === '42501' ||
    code === '28P01' ||
    msg.includes('invalid api key') ||
    msg.includes('jwt') ||
    msg.includes('permission denied')
  ) {
    return false;
  }

  if (
    status >= 500 ||
    code === '57014' ||
    code.startsWith('08') ||
    msg.includes('timed out') ||
    msg.includes('timeout') ||
    msg.includes('abort') ||
    msg.includes('fetch failed') ||
    msg.includes('network') ||
    msg.includes('econnreset') ||
    msg.includes('etimedout') ||
    msg.includes('socket')
  ) {
    return true;
  }

  return Boolean(thrownErr);
}

async function executeQuotaRpc<T = any>(
  serviceClient: SupabaseClient,
  fnName: string,
  params: Record<string, unknown>,
  label: string
): Promise<{ data: T | null; error: { code?: string; message?: string; status?: number } | null }> {
  let lastError: { code?: string; message?: string; status?: number } | null = null;

  for (let attempt = 1; attempt <= MAX_RPC_ATTEMPTS; attempt++) {
    try {
      const result = await withTimeout(
        Promise.resolve(serviceClient.rpc(fnName, params)),
        RPC_TIMEOUT_MS,
        label
      );

      if (!result.error) {
        return { data: (result.data as T) ?? null, error: null };
      }

      lastError = result.error as { code?: string; message?: string; status?: number };
      if (!isRetryableQuotaRpcFailure(lastError) || attempt >= MAX_RPC_ATTEMPTS) {
        return { data: (result.data as T) ?? null, error: lastError };
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      lastError = { message };
      if (!isRetryableQuotaRpcFailure(lastError, err) || attempt >= MAX_RPC_ATTEMPTS) {
        throw err;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, RPC_RETRY_DELAY_MS));
  }

  return { data: null, error: lastError };
}

export async function resolveVerifiedUserDefault(): Promise<ResolvedQuotaUser> {
  try {
    const supabase = await createServerSupabaseClient();
    if (!supabase) return { status: 'guest', userId: null };

    const {
      data: { user },
      error,
    } = await withTimeout(supabase.auth.getUser(), AUTH_TIMEOUT_MS, 'quota.auth.getUser');

    if (error || !user?.id) {
      return { status: 'guest', userId: null };
    }

    const userRecord = user as unknown as Record<string, unknown>;
    const hasEmailConfirmField =
      'email_confirmed_at' in userRecord || 'confirmed_at' in userRecord;

    if (hasEmailConfirmField) {
      const confirmed = Boolean(userRecord.email_confirmed_at || userRecord.confirmed_at);
      if (!confirmed) {
        return { status: 'unverified', userId: user.id };
      }
    }

    return { status: 'verified', userId: user.id };
  } catch {
    return { status: 'guest', userId: null };
  }
}

function normalizeSnapshot(raw: any): QuotaSnapshot {
  const ownerType = raw?.ownerType === 'user' ? 'user' : 'guest';
  const rawBalances = raw?.balances || {};

  if (ownerType === 'guest') {
    const shared = Math.max(
      0,
      Number.isFinite(Number(raw?.sharedRemaining))
        ? Number(raw.sharedRemaining)
        : Number(rawBalances.message_analysis ?? 0)
    );
    return {
      ownerType: 'guest',
      planTier: 'guest_trial',
      nonRenewing: true,
      sharedRemaining: shared,
      sharedLimit: GUEST_INITIAL_SHARED_CREDITS,
      balances: {
        message_analysis: shared,
        document_scan: shared,
        fact_check: shared,
        url_investigation: shared,
      },
      perCapabilityLimit: null,
      totalRemaining: shared,
      claimedByUser: Boolean(raw?.claimedByUser),
    };
  }

  const msg = Math.max(0, Number(rawBalances.message_analysis ?? 0));
  const doc = Math.max(0, Number(rawBalances.document_scan ?? 0));
  const fc = Math.max(0, Number(rawBalances.fact_check ?? 0));
  const url = Math.max(0, Number(rawBalances.url_investigation ?? 0));
  return {
    ownerType: 'user',
    planTier: raw?.planTier === 'pro' || raw?.planTier === 'business' ? raw.planTier : 'free',
    nonRenewing: true,
    sharedRemaining: null,
    sharedLimit: null,
    balances: {
      message_analysis: msg,
      document_scan: doc,
      fact_check: fc,
      url_investigation: url,
    },
    perCapabilityLimit: USER_INITIAL_CAPABILITY_CREDITS,
    totalRemaining: msg + doc + fc + url,
    claimedByUser: false,
  };
}

function buildLocalGuestSnapshot(rec: LocalGuestRecord): QuotaSnapshot {
  return {
    ownerType: 'guest',
    planTier: 'guest_trial',
    nonRenewing: true,
    sharedRemaining: rec.balance,
    sharedLimit: GUEST_INITIAL_SHARED_CREDITS,
    balances: {
      message_analysis: rec.balance,
      document_scan: rec.balance,
      fact_check: rec.balance,
      url_investigation: rec.balance,
    },
    perCapabilityLimit: null,
    totalRemaining: rec.balance,
    claimedByUser: Boolean(rec.claimedByUserId),
  };
}

function buildLocalUserSnapshot(rec: LocalUserRecord): QuotaSnapshot {
  const { message_analysis, document_scan, fact_check, url_investigation } = rec.balances;
  return {
    ownerType: 'user',
    planTier: 'free',
    nonRenewing: true,
    sharedRemaining: null,
    sharedLimit: null,
    balances: { ...rec.balances },
    perCapabilityLimit: USER_INITIAL_CAPABILITY_CREDITS,
    totalRemaining: message_analysis + document_scan + fact_check + url_investigation,
    claimedByUser: false,
  };
}

function resolveCanonicalLocalGuest(store: LocalQuotaStore, startHash: string): LocalGuestRecord | null {
  let currHash = startHash;
  let depth = 0;
  let rec = store.guests.get(currHash) || null;
  while (rec && rec.supersededByHash && depth < 10) {
    depth++;
    currHash = rec.supersededByHash;
    rec = store.guests.get(currHash) || null;
  }
  return rec;
}

function ensureLocalGuest(
  store: LocalQuotaStore,
  guestHash: string,
  createIfMissing: boolean
): { ok: true; record: LocalGuestRecord } | { ok: false; errorCode: QuotaErrorCode } {
  const existing = resolveCanonicalLocalGuest(store, guestHash);
  if (existing) {
    return { ok: true, record: existing };
  }

  if (!createIfMissing) {
    return { ok: false, errorCode: 'invalid_guest_token' };
  }

  const created: LocalGuestRecord = {
    guestHash,
    accountKey: `guest:${guestHash}`,
    balance: GUEST_INITIAL_SHARED_CREDITS,
    initialGrantIssued: true,
  };
  store.guests.set(guestHash, created);
  return { ok: true, record: created };
}

function ensureLocalUser(
  store: LocalQuotaStore,
  userId: string,
  claimGuestHash: string | null
): LocalUserRecord {
  if (claimGuestHash) {
    const guestRec = resolveCanonicalLocalGuest(store, claimGuestHash);
    if (guestRec) {
      if (!guestRec.claimedByUserId) {
        guestRec.claimedByUserId = userId;
        guestRec.claimedAt = new Date().toISOString();
      }
    } else {
      store.guests.set(claimGuestHash, {
        guestHash: claimGuestHash,
        accountKey: `guest:${claimGuestHash}`,
        balance: GUEST_INITIAL_SHARED_CREDITS,
        initialGrantIssued: true,
        claimedByUserId: userId,
        claimedAt: new Date().toISOString(),
      });
    }
  }

  const existing = store.users.get(userId);
  if (existing) {
    if (claimGuestHash && !existing.claimedGuestHash) {
      existing.claimedGuestHash = claimGuestHash;
    }
    return existing;
  }

  const created: LocalUserRecord = {
    userId,
    accountKey: `user:${userId}`,
    initialGrantIssued: true,
    claimedGuestHash: claimGuestHash || undefined,
    balances: {
      message_analysis: USER_INITIAL_CAPABILITY_CREDITS,
      document_scan: USER_INITIAL_CAPABILITY_CREDITS,
      fact_check: USER_INITIAL_CAPABILITY_CREDITS,
      url_investigation: USER_INITIAL_CAPABILITY_CREDITS,
    },
  };
  store.users.set(userId, created);
  return created;
}

export async function rotateGuestToken(
  req: Request,
  deps: QuotaDependencies = {}
): Promise<{
  ok: boolean;
  status: 200 | 403 | 503;
  snapshot?: QuotaSnapshot;
  cookieToSet?: { name: string; value: string; isHttps: boolean };
  error?: string;
  errorCode?: QuotaErrorCode;
}> {
  const env = deps.env || process.env;
  const rawCookie = extractGuestCookieValue(req);
  if (rawCookie === null) {
    return {
      ok: false,
      status: 403,
      errorCode: 'invalid_guest_token',
      error: 'No active guest session cookie to rotate.',
    };
  }

  const verified = verifySignedGuestToken(rawCookie, env);
  if (!verified.valid) {
    if (verified.reason === 'unconfigured') {
      return {
        ok: false,
        status: 503,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota signing service is unavailable.',
      };
    }
    return {
      ok: false,
      status: 403,
      errorCode: 'invalid_guest_token',
      error: 'Guest session token is invalid or tampered.',
    };
  }

  const minted = mintSignedGuestToken(env);
  if (!minted) {
    return {
      ok: false,
      status: 503,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota signing service is unavailable.',
    };
  }

  const https = isHttpsRequest(req, env);
  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  if (serviceClient) {
    try {
      const { data, error } = await executeQuotaRpc(
        serviceClient,
        'rotate_guest_identity',
        {
          p_old_hash: verified.guestHash,
          p_new_hash: minted.guestHash,
        },
        'rotate_guest_identity'
      );

      if (!error && data?.ok) {
        return {
          ok: true,
          status: 200,
          snapshot: normalizeSnapshot(data.snapshot),
          cookieToSet: { name: GUEST_COOKIE_NAME, value: minted.cookieValue, isHttps: https },
        };
      }

      if (!isProductionEnv(env) && isMissingQuotaMigrationError(error)) {
        noteDevMigrationFallbackOnce('rotate_guest_identity');
      } else {
        const isInvalidToken =
          data?.errorCode === 'unrecognized_guest_token' ||
          data?.errorCode === 'token_already_rotated' ||
          data?.errorCode === 'invalid_guest_token';
        return {
          ok: false,
          status: isInvalidToken ? 403 : 503,
          errorCode: isInvalidToken ? 'invalid_guest_token' : 'quota_service_unavailable',
          error: 'Could not rotate guest session token safely.',
        };
      }
    } catch {
      return {
        ok: false,
        status: 503,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota service unavailable during token rotation.',
      };
    }
  }

  if (isProductionEnv(env)) {
    return {
      ok: false,
      status: 503,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota database is unconfigured.',
    };
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const oldRec = store.guests.get(verified.guestHash);
  if (!oldRec || oldRec.supersededByHash) {
    return {
      ok: false,
      status: 403,
      errorCode: 'invalid_guest_token',
      error: 'Guest token is unrecognized or already rotated.',
    };
  }

  const newRec: LocalGuestRecord = {
    guestHash: minted.guestHash,
    rotatedFromHash: verified.guestHash,
    claimedByUserId: oldRec.claimedByUserId,
    claimedAt: oldRec.claimedAt,
    accountKey: `guest:${minted.guestHash}`,
    balance: oldRec.balance,
    initialGrantIssued: true,
  };
  oldRec.supersededByHash = minted.guestHash;
  oldRec.balance = 0;
  store.guests.set(minted.guestHash, newRec);

  return {
    ok: true,
    status: 200,
    snapshot: buildLocalGuestSnapshot(newRec),
    cookieToSet: { name: GUEST_COOKIE_NAME, value: minted.cookieValue, isHttps: https },
  };
}

/**
 * Resolves the authoritative quota state for a GET /api/quota or auth callback sync.
 * Initializes guest (12 shared) or verified registered user (5/5/5/5) balances idempotently.
 */
export async function getOrInitializeQuotaSnapshot(
  req: Request,
  deps: QuotaDependencies = {}
): Promise<QuotaSnapshotOutcome> {
  const env = deps.env || process.env;
  const resolveUser = deps.resolveUser || resolveVerifiedUserDefault;
  const userState = await resolveUser();
  const https = isHttpsRequest(req, env);

  const rawCookie = extractGuestCookieValue(req);
  let validCookieGuestHash: string | null = null;
  let hadInvalidCookie = false;
  let hadUnconfiguredSigningKey = false;

  if (rawCookie !== null) {
    const verified = verifySignedGuestToken(rawCookie, env);
    if (verified.valid) {
      validCookieGuestHash = verified.guestHash;
    } else if (verified.reason === 'unconfigured') {
      hadUnconfiguredSigningKey = true;
    } else {
      hadInvalidCookie = true;
    }
  }

  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  if (userState.status === 'unverified') {
    return {
      ok: false,
      status: 403,
      errorCode: 'email_verification_required',
      requiresVerification: true,
      error: 'Please verify your email address to activate your registered account investigation credits.',
    };
  }

  if (userState.status === 'verified' && userState.userId) {
    if (serviceClient) {
      try {
        const { data, error } = await executeQuotaRpc(
          serviceClient,
          'ensure_user_quota',
          {
            p_user_id: userState.userId,
            p_claim_guest_hash: validCookieGuestHash,
          },
          'ensure_user_quota'
        );

        if (!error && data?.ok && data?.snapshot) {
          return {
            ok: true,
            status: 200,
            snapshot: normalizeSnapshot(data.snapshot),
          };
        }

        if (!isProductionEnv(env) && isMissingQuotaMigrationError(error)) {
          noteDevMigrationFallbackOnce('ensure_user_quota');
        } else {
          console.warn('Quota user initialization error:', redactSecrets(error?.message || 'invalid_rpc_response'));
          return {
            ok: false,
            status: 503,
            errorCode: 'quota_service_unavailable',
            error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
          };
        }
      } catch (err: unknown) {
        console.warn(
          'Quota user RPC exception:',
          redactSecrets(err instanceof Error ? err.message : String(err))
        );
        return {
          ok: false,
          status: 503,
          errorCode: 'quota_service_unavailable',
          error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
        };
      }
    }

    if (isProductionEnv(env)) {
      return {
        ok: false,
        status: 503,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is not configured.',
      };
    }

    const store = deps.localStore || getGlobalLocalQuotaStore();
    const rec = ensureLocalUser(store, userState.userId, validCookieGuestHash);
    return {
      ok: true,
      status: 200,
      snapshot: buildLocalUserSnapshot(rec),
    };
  }

  if (hadUnconfiguredSigningKey || !resolveSigningKey(env)) {
    return {
      ok: false,
      status: 503,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota protection service is not configured.',
    };
  }

  // Guest path: reject malformed/forged cookies cleanly without issuing fresh 12 credits
  if (hadInvalidCookie) {
    return {
      ok: false,
      status: 403,
      errorCode: 'invalid_guest_token',
      error: 'Invalid or tampered guest session token. Please sign in or clear invalid browser cookies.',
    };
  }

  let cookieToSet: { name: string; value: string; isHttps: boolean } | undefined;
  let guestHash = validCookieGuestHash;
  const isNewGuest = !guestHash;

  if (!guestHash) {
    const minted = mintSignedGuestToken(env);
    if (!minted) {
      return {
        ok: false,
        status: 503,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is not configured.',
      };
    }
    guestHash = minted.guestHash;
    cookieToSet = {
      name: GUEST_COOKIE_NAME,
      value: minted.cookieValue,
      isHttps: https,
    };
  }

  if (serviceClient) {
    try {
      const { data, error } = await executeQuotaRpc(
        serviceClient,
        'ensure_guest_quota',
        {
          p_guest_hash: guestHash,
          p_initial_credits: GUEST_INITIAL_SHARED_CREDITS,
          p_create_if_missing: isNewGuest,
        },
        'ensure_guest_quota'
      );

      if (error) {
        if (!isProductionEnv(env) && isMissingQuotaMigrationError(error)) {
          noteDevMigrationFallbackOnce('ensure_guest_quota');
        } else {
          console.warn('Quota guest initialization error:', redactSecrets(error.message || 'rpc_error'));
          return {
            ok: false,
            status: 503,
            errorCode: 'quota_service_unavailable',
            error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
          };
        }
      } else if (!data?.ok) {
        return {
          ok: false,
          status: 403,
          errorCode: 'invalid_guest_token',
          error: 'Unrecognized guest session token. Please sign in to continue investigating.',
        };
      } else {
        return {
          ok: true,
          status: 200,
          snapshot: normalizeSnapshot(data.snapshot),
          cookieToSet,
        };
      }
    } catch (err: unknown) {
      console.warn(
        'Quota guest RPC exception:',
        redactSecrets(err instanceof Error ? err.message : String(err))
      );
      return {
        ok: false,
        status: 503,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
      };
    }
  }

  if (isProductionEnv(env)) {
    return {
      ok: false,
      status: 503,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota protection service is not configured.',
    };
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const localGuest = ensureLocalGuest(store, guestHash, isNewGuest);
  if (!localGuest.ok) {
    return {
      ok: false,
      status: 403,
      errorCode: 'invalid_guest_token',
      error: 'Unrecognized guest session token. Please sign in to continue investigating.',
    };
  }

  return {
    ok: true,
    status: 200,
    snapshot: buildLocalGuestSnapshot(localGuest.record),
    cookieToSet,
  };
}

/**
 * Reserves 1 investigation credit atomically BEFORE executing AI, Serper, or URLhaus work.
 */
export async function reserveInvestigationQuota(
  req: Request,
  capability: QuotaCapability,
  deps: QuotaDependencies = {}
): Promise<QuotaCheckOutcome> {
  const env = deps.env || process.env;
  const resolveUser = deps.resolveUser || resolveVerifiedUserDefault;
  const userState = await resolveUser();
  const https = isHttpsRequest(req, env);

  if (userState.status === 'unverified') {
    return {
      allowed: false,
      status: 403,
      capability,
      errorCode: 'email_verification_required',
      requiresVerification: true,
      error: 'Please verify your email address before running registered-account investigations.',
    };
  }

  const rawCookie = extractGuestCookieValue(req);
  let validCookieGuestHash: string | null = null;
  let hadInvalidCookie = false;
  let hadUnconfiguredSigningKey = false;

  if (rawCookie !== null) {
    const verified = verifySignedGuestToken(rawCookie, env);
    if (verified.valid) {
      validCookieGuestHash = verified.guestHash;
    } else if (verified.reason === 'unconfigured') {
      hadUnconfiguredSigningKey = true;
    } else {
      hadInvalidCookie = true;
    }
  }

  const idempotencyHeader = req.headers?.get?.('x-aegis-idempotency-key')?.trim() || null;
  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  // Verified authenticated user path
  if (userState.status === 'verified' && userState.userId) {
    const accountKey = `user:${userState.userId}`;
    if (serviceClient) {
      try {
        const { data: initData, error: initError } = await executeQuotaRpc(
          serviceClient,
          'ensure_user_quota',
          {
            p_user_id: userState.userId,
            p_claim_guest_hash: validCookieGuestHash,
          },
          'ensure_user_quota'
        );

        let devFallback = false;
        if (initError || !initData?.ok) {
          if (!isProductionEnv(env) && isMissingQuotaMigrationError(initError)) {
            noteDevMigrationFallbackOnce('reserve.ensure_user_quota');
            devFallback = true;
          } else {
            return {
              allowed: false,
              status: 503,
              capability,
              errorCode: 'quota_service_unavailable',
              error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
            };
          }
        }

        if (!devFallback) {
          const { data: resData, error: resError } = await executeQuotaRpc(
            serviceClient,
            'reserve_investigation_quota',
            {
              p_account_key: accountKey,
              p_capability: capability,
              p_idempotency_key: idempotencyHeader,
            },
            'reserve_investigation_quota'
          );

          if (resError || !resData) {
            if (!isProductionEnv(env) && isMissingQuotaMigrationError(resError)) {
              noteDevMigrationFallbackOnce('reserve_investigation_quota');
              devFallback = true;
            } else {
              return {
                allowed: false,
                status: 503,
                capability,
                errorCode: 'quota_service_unavailable',
                error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
              };
            }
          } else {
            const snapshot = normalizeSnapshot(resData.snapshot);
            if (!resData.allowed) {
              const capLabel = CAPABILITY_LABELS[capability];
              return {
                allowed: false,
                status: 403,
                capability,
                errorCode: 'quota_exhausted',
                requiresRegistration: false,
                snapshot,
                error: `You have used all 5 ${capLabel} credits included with your account. Other capabilities with remaining balance remain available.`,
              };
            }

            return {
              allowed: true,
              status: 200,
              capability,
              snapshot,
              reservation: {
                reservationId: String(resData.reservationId),
                accountKey,
                bucket: String(resData.bucket || capability),
                capability,
                ownerType: 'user',
                mode: 'distributed_supabase',
                snapshot,
              },
            };
          }
        }
      } catch (err: unknown) {
        console.warn(
          'Quota reserve user RPC exception:',
          redactSecrets(err instanceof Error ? err.message : String(err))
        );
        return {
          allowed: false,
          status: 503,
          capability,
          errorCode: 'quota_service_unavailable',
          error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
        };
      }
    }

    if (isProductionEnv(env)) {
      return {
        allowed: false,
        status: 503,
        capability,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is not configured.',
      };
    }

    const store = deps.localStore || getGlobalLocalQuotaStore();
    const rec = ensureLocalUser(store, userState.userId, validCookieGuestHash);

    if (idempotencyHeader) {
      const existingId = store.idempotency.get(`${rec.accountKey}:${idempotencyHeader}`);
      if (existingId && store.reservations.has(existingId)) {
        const snapshot = buildLocalUserSnapshot(rec);
        return {
          allowed: true,
          status: 200,
          capability,
          snapshot,
          reservation: {
            reservationId: existingId,
            accountKey: rec.accountKey,
            bucket: capability,
            capability,
            ownerType: 'user',
            mode: 'local_dev',
            snapshot,
          },
        };
      }
    }

    if (rec.balances[capability] < 1) {
      const capLabel = CAPABILITY_LABELS[capability];
      return {
        allowed: false,
        status: 403,
        capability,
        errorCode: 'quota_exhausted',
        requiresRegistration: false,
        snapshot: buildLocalUserSnapshot(rec),
        error: `You have used all 5 ${capLabel} credits included with your account. Other capabilities with remaining balance remain available.`,
      };
    }

    rec.balances[capability] -= 1;
    const reservationId = `local-${randomBytes(8).toString('hex')}`;
    store.reservations.set(reservationId, {
      id: reservationId,
      accountKey: rec.accountKey,
      ownerType: 'user',
      bucket: capability,
      capability,
      status: 'reserved',
      idempotencyKey: idempotencyHeader || undefined,
      createdAtMs: deps.nowMs ? deps.nowMs() : Date.now(),
    });
    if (idempotencyHeader) {
      store.idempotency.set(`${rec.accountKey}:${idempotencyHeader}`, reservationId);
    }

    const snapshot = buildLocalUserSnapshot(rec);
    return {
      allowed: true,
      status: 200,
      capability,
      snapshot,
      reservation: {
        reservationId,
        accountKey: rec.accountKey,
        bucket: capability,
        capability,
        ownerType: 'user',
        mode: 'local_dev',
        snapshot,
      },
    };
  }

  // Guest path
  if (hadUnconfiguredSigningKey || !resolveSigningKey(env)) {
    return {
      allowed: false,
      status: 503,
      capability,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota protection service is not configured.',
    };
  }

  if (hadInvalidCookie) {
    return {
      allowed: false,
      status: 403,
      capability,
      errorCode: 'invalid_guest_token',
      requiresRegistration: true,
      error: 'Invalid or tampered guest session token. Please register or sign in to continue.',
    };
  }

  let cookieToSet: { name: string; value: string; isHttps: boolean } | undefined;
  let guestHash = validCookieGuestHash;
  const isNewGuest = !guestHash;

  if (!guestHash) {
    const minted = mintSignedGuestToken(env);
    if (!minted) {
      return {
        allowed: false,
        status: 503,
        capability,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is not configured.',
      };
    }
    guestHash = minted.guestHash;
    cookieToSet = {
      name: GUEST_COOKIE_NAME,
      value: minted.cookieValue,
      isHttps: https,
    };
  }

  if (serviceClient) {
    try {
      const { data: initData, error: initError } = await executeQuotaRpc(
        serviceClient,
        'ensure_guest_quota',
        {
          p_guest_hash: guestHash,
          p_initial_credits: GUEST_INITIAL_SHARED_CREDITS,
          p_create_if_missing: isNewGuest,
        },
        'ensure_guest_quota'
      );

      let devFallback = false;
      if (initError) {
        if (!isProductionEnv(env) && isMissingQuotaMigrationError(initError)) {
          noteDevMigrationFallbackOnce('reserve.ensure_guest_quota');
          devFallback = true;
        } else {
          return {
            allowed: false,
            status: 503,
            capability,
            errorCode: 'quota_service_unavailable',
            error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
          };
        }
      }

      if (!devFallback) {
        if (!initData?.ok) {
          return {
            allowed: false,
            status: 403,
            capability,
            errorCode: 'invalid_guest_token',
            requiresRegistration: true,
            error: 'Unrecognized guest session token. Please create an account or sign in to continue.',
          };
        }

        const accountKey = String(initData.accountKey || `guest:${guestHash}`);

        const { data: resData, error: resError } = await executeQuotaRpc(
          serviceClient,
          'reserve_investigation_quota',
          {
            p_account_key: accountKey,
            p_capability: capability,
            p_idempotency_key: idempotencyHeader,
          },
          'reserve_investigation_quota'
        );

        if (resError || !resData) {
          if (!isProductionEnv(env) && isMissingQuotaMigrationError(resError)) {
            noteDevMigrationFallbackOnce('reserve.guest_reserve');
            devFallback = true;
          } else {
            return {
              allowed: false,
              status: 503,
              capability,
              errorCode: 'quota_service_unavailable',
              error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
            };
          }
        } else {
          const snapshot = normalizeSnapshot(resData.snapshot);
          if (!resData.allowed) {
            return {
              allowed: false,
              status: 403,
              capability,
              errorCode: 'quota_exhausted',
              requiresRegistration: true,
              snapshot,
              cookieToSet,
              error:
                'You have used all 12 guest investigations. Create a free account and verify your email to unlock 20 additional credits (5 per analysis tool).',
            };
          }

          return {
            allowed: true,
            status: 200,
            capability,
            snapshot,
            cookieToSet,
            reservation: {
              reservationId: String(resData.reservationId),
              accountKey,
              bucket: 'guest_shared',
              capability,
              ownerType: 'guest',
              mode: 'distributed_supabase',
              snapshot,
              cookieToSet,
            },
          };
        }
      }
    } catch (err: unknown) {
      console.warn(
        'Quota reserve guest RPC exception:',
        redactSecrets(err instanceof Error ? err.message : String(err))
      );
      return {
        allowed: false,
        status: 503,
        capability,
        errorCode: 'quota_service_unavailable',
        error: 'Usage quota protection service is temporarily unavailable. Please retry shortly.',
      };
    }
  }

  if (isProductionEnv(env)) {
    return {
      allowed: false,
      status: 503,
      capability,
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota protection service is not configured.',
    };
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const localGuest = ensureLocalGuest(store, guestHash, isNewGuest);
  if (!localGuest.ok) {
    return {
      allowed: false,
      status: 403,
      capability,
      errorCode: 'invalid_guest_token',
      requiresRegistration: true,
      error: 'Unrecognized guest session token. Please create an account or sign in to continue.',
    };
  }

  const rec = localGuest.record;
  if (idempotencyHeader) {
    const existingId = store.idempotency.get(`${rec.accountKey}:${idempotencyHeader}`);
    if (existingId && store.reservations.has(existingId)) {
      const snapshot = buildLocalGuestSnapshot(rec);
      return {
        allowed: true,
        status: 200,
        capability,
        snapshot,
        cookieToSet,
        reservation: {
          reservationId: existingId,
          accountKey: rec.accountKey,
          bucket: 'guest_shared',
          capability,
          ownerType: 'guest',
          mode: 'local_dev',
          snapshot,
          cookieToSet,
        },
      };
    }
  }

  if (rec.balance < 1) {
    return {
      allowed: false,
      status: 403,
      capability,
      errorCode: 'quota_exhausted',
      requiresRegistration: true,
      snapshot: buildLocalGuestSnapshot(rec),
      cookieToSet,
      error:
        'You have used all 12 guest investigations. Create a free account and verify your email to unlock 20 additional credits (5 per analysis tool).',
    };
  }

  rec.balance -= 1;
  const reservationId = `local-${randomBytes(8).toString('hex')}`;
  store.reservations.set(reservationId, {
    id: reservationId,
    accountKey: rec.accountKey,
    ownerType: 'guest',
    bucket: 'guest_shared',
    capability,
    status: 'reserved',
    idempotencyKey: idempotencyHeader || undefined,
    createdAtMs: deps.nowMs ? deps.nowMs() : Date.now(),
  });
  if (idempotencyHeader) {
    store.idempotency.set(`${rec.accountKey}:${idempotencyHeader}`, reservationId);
  }

  const snapshot = buildLocalGuestSnapshot(rec);
  return {
    allowed: true,
    status: 200,
    capability,
    snapshot,
    cookieToSet,
    reservation: {
      reservationId,
      accountKey: rec.accountKey,
      bucket: 'guest_shared',
      capability,
      ownerType: 'guest',
      mode: 'local_dev',
      snapshot,
      cookieToSet,
    },
  };
}

/**
 * Commits a reserved credit once investigation output succeeds.
 */
export async function commitQuotaReservation(
  reservation: QuotaReservationHandle | undefined,
  deps: QuotaDependencies = {}
): Promise<QuotaSnapshot | undefined> {
  if (!reservation) return undefined;
  const env = deps.env || process.env;
  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  if (reservation.mode === 'distributed_supabase' && serviceClient) {
    try {
      const { data } = await executeQuotaRpc(
        serviceClient,
        'finalize_investigation_quota',
        {
          p_reservation_id: reservation.reservationId,
          p_outcome: 'commit',
          p_reason: null,
        },
        'finalize_investigation_quota(commit)'
      );
      if (data?.snapshot) {
        return normalizeSnapshot(data.snapshot);
      }
    } catch (err: unknown) {
      console.warn(
        'Non-fatal quota commit warning:',
        redactSecrets(err instanceof Error ? err.message : String(err))
      );
    }
    return reservation.snapshot;
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const resRec = store.reservations.get(reservation.reservationId);
  if (resRec && resRec.status === 'reserved') {
    resRec.status = 'committed';
  }
  return reservation.snapshot;
}

/**
 * Refunds a reserved credit at most once if downstream analysis fails or aborts.
 */
export async function refundQuotaReservation(
  reservation: QuotaReservationHandle | undefined,
  reason = 'downstream_failure',
  deps: QuotaDependencies = {}
): Promise<QuotaSnapshot | undefined> {
  if (!reservation) return undefined;
  const env = deps.env || process.env;
  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  if (reservation.mode === 'distributed_supabase' && serviceClient) {
    try {
      const { data } = await executeQuotaRpc(
        serviceClient,
        'finalize_investigation_quota',
        {
          p_reservation_id: reservation.reservationId,
          p_outcome: 'refund',
          p_reason: redactSecrets(reason).slice(0, 200),
        },
        'finalize_investigation_quota(refund)'
      );
      if (data?.snapshot) {
        return normalizeSnapshot(data.snapshot);
      }
    } catch (err: unknown) {
      console.warn(
        'Non-fatal quota refund warning:',
        redactSecrets(err instanceof Error ? err.message : String(err))
      );
    }
    return reservation.snapshot;
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const resRec = store.reservations.get(reservation.reservationId);
  if (!resRec || resRec.status !== 'reserved') {
    return reservation.snapshot;
  }

  resRec.status = 'refunded';
  resRec.failureReason = redactSecrets(reason).slice(0, 200);

  if (resRec.ownerType === 'guest') {
    const hash = resRec.accountKey.replace(/^guest:/, '');
    const guestRec = resolveCanonicalLocalGuest(store, hash);
    if (guestRec) {
      guestRec.balance += 1;
      return buildLocalGuestSnapshot(guestRec);
    }
  } else {
    const uid = resRec.accountKey.replace(/^user:/, '');
    const userRec = store.users.get(uid);
    if (userRec) {
      userRec.balances[resRec.capability] += 1;
      return buildLocalUserSnapshot(userRec);
    }
  }

  return reservation.snapshot;
}

export interface StaleReservationRecoveryOutcome {
  ok: boolean;
  status: 200 | 503;
  mode?: 'distributed_supabase' | 'local_dev';
  minAgeSeconds: number;
  recoveredCount: number;
  skippedCount: number;
  recoveredReservationIds: string[];
  error?: string;
  errorCode?: QuotaErrorCode;
}

const DEFAULT_STALE_RESERVATION_AGE_SECONDS = 600; // 10 minutes
const ENFORCED_MIN_STALE_AGE_SECONDS = 300; // 5 minutes (>= 5x max 60s route budget)
const DEFAULT_STALE_RECOVERY_BATCH_LIMIT = 100;

/**
 * Safely recovers orphaned `reserved` quota reservations older than the conservative timeout threshold.
 * Intended strictly for server-side / scheduled service_role execution (never exposed as a public endpoint).
 */
export async function recoverStaleQuotaReservations(
  options: { minAgeSeconds?: number; limit?: number } = {},
  deps: QuotaDependencies = {}
): Promise<StaleReservationRecoveryOutcome> {
  const env = deps.env || process.env;
  const minAgeSeconds = Math.max(
    ENFORCED_MIN_STALE_AGE_SECONDS,
    Math.floor(Number.isFinite(options.minAgeSeconds) ? Number(options.minAgeSeconds) : DEFAULT_STALE_RESERVATION_AGE_SECONDS)
  );
  const limit = Math.max(
    1,
    Math.min(
      500,
      Math.floor(Number.isFinite(options.limit) ? Number(options.limit) : DEFAULT_STALE_RECOVERY_BATCH_LIMIT)
    )
  );

  const serviceClient =
    deps.serviceClient !== undefined ? deps.serviceClient : getQuotaServiceClient(env);

  if (serviceClient) {
    try {
      const { data, error } = await executeQuotaRpc(
        serviceClient,
        'recover_stale_quota_reservations',
        {
          p_min_age_seconds: minAgeSeconds,
          p_limit: limit,
        },
        'recover_stale_quota_reservations'
      );

      if (!error && data?.ok) {
        return {
          ok: true,
          status: 200,
          mode: 'distributed_supabase',
          minAgeSeconds: Number(data.minAgeSeconds ?? minAgeSeconds),
          recoveredCount: Number(data.recoveredCount ?? 0),
          skippedCount: Number(data.skippedCount ?? 0),
          recoveredReservationIds: Array.isArray(data.recoveredReservationIds)
            ? data.recoveredReservationIds.map(String)
            : [],
        };
      }

      if (!isProductionEnv(env) && isMissingQuotaMigrationError(error)) {
        noteDevMigrationFallbackOnce('recover_stale_quota_reservations');
      } else {
        console.warn(
          'Quota stale reservation recovery error:',
          redactSecrets(error?.message || 'invalid_rpc_response')
        );
        return {
          ok: false,
          status: 503,
          minAgeSeconds,
          recoveredCount: 0,
          skippedCount: 0,
          recoveredReservationIds: [],
          errorCode: 'quota_service_unavailable',
          error: 'Quota recovery service is unavailable.',
        };
      }
    } catch (err: unknown) {
      console.warn(
        'Quota stale reservation recovery exception:',
        redactSecrets(err instanceof Error ? err.message : String(err))
      );
      return {
        ok: false,
        status: 503,
        minAgeSeconds,
        recoveredCount: 0,
        skippedCount: 0,
        recoveredReservationIds: [],
        errorCode: 'quota_service_unavailable',
        error: 'Quota recovery service failed.',
      };
    }
  }

  if (isProductionEnv(env)) {
    return {
      ok: false,
      status: 503,
      minAgeSeconds,
      recoveredCount: 0,
      skippedCount: 0,
      recoveredReservationIds: [],
      errorCode: 'quota_service_unavailable',
      error: 'Usage quota protection database is not configured.',
    };
  }

  const store = deps.localStore || getGlobalLocalQuotaStore();
  const nowMs = deps.nowMs ? deps.nowMs() : Date.now();
  const cutoffMs = nowMs - minAgeSeconds * 1000;
  const recoveredIds: string[] = [];

  for (const resRec of store.reservations.values()) {
    if (recoveredIds.length >= limit) break;
    if (resRec.status !== 'reserved') continue;
    const createdMs = typeof resRec.createdAtMs === 'number' ? resRec.createdAtMs : nowMs;
    if (createdMs > cutoffMs) continue;

    resRec.status = 'refunded';
    resRec.failureReason = 'stale_reservation_recovery';

    if (resRec.ownerType === 'guest') {
      const hash = resRec.accountKey.replace(/^guest:/, '');
      const guestRec = resolveCanonicalLocalGuest(store, hash);
      if (guestRec) {
        guestRec.balance += 1;
      }
    } else {
      const uid = resRec.accountKey.replace(/^user:/, '');
      const userRec = store.users.get(uid);
      if (userRec) {
        userRec.balances[resRec.capability] += 1;
      }
    }
    recoveredIds.push(resRec.id);
  }

  return {
    ok: true,
    status: 200,
    mode: 'local_dev',
    minAgeSeconds,
    recoveredCount: recoveredIds.length,
    skippedCount: 0,
    recoveredReservationIds: recoveredIds,
  };
}

export interface QuotaHealthDiagnostic {
  status: 'operational' | 'unconfigured' | 'missing_migration' | 'unavailable';
  guestSecretConfigured: boolean;
  serviceClientConfigured: boolean;
  mode: 'distributed_supabase' | 'local_dev' | 'fail_closed';
  detail: string;
}

/**
 * Non-destructive read-only health check for admin diagnostics.
 * Verifies guest signing secret and distributed quota table/RPC reachability without creating accounts or revealing secrets.
 */
export async function probeQuotaHealth(
  env: NodeJS.ProcessEnv = process.env,
  overrideClient?: SupabaseClient | null
): Promise<QuotaHealthDiagnostic> {
  const guestSecretConfigured = isValidGuestTokenSecret(env.GUEST_TOKEN_SECRET);
  const client = overrideClient !== undefined ? overrideClient : getQuotaServiceClient(env);
  const serviceClientConfigured = Boolean(client);
  const prod = isProductionEnv(env);

  if (prod && !guestSecretConfigured) {
    return {
      status: 'unconfigured',
      guestSecretConfigured: false,
      serviceClientConfigured,
      mode: 'fail_closed',
      detail: 'GUEST_TOKEN_SECRET is missing or invalid in production; quota endpoints fail closed.',
    };
  }

  if (!client) {
    return {
      status: prod ? 'unconfigured' : 'operational',
      guestSecretConfigured,
      serviceClientConfigured: false,
      mode: prod ? 'fail_closed' : 'local_dev',
      detail: prod
        ? 'Supabase service-role quota client is not configured in production.'
        : 'Running with non-production local quota store.',
    };
  }

  try {
    const { error } = await withTimeout(
      Promise.resolve(client.from('quota_accounts').select('account_key', { head: true, count: 'exact' }).limit(1)),
      RPC_TIMEOUT_MS,
      'probeQuotaHealth'
    );

    if (!error) {
      return {
        status: 'operational',
        guestSecretConfigured,
        serviceClientConfigured: true,
        mode: 'distributed_supabase',
        detail: 'Distributed Supabase quota tables and service-role access verified.',
      };
    }

    if (isMissingQuotaMigrationError(error)) {
      return {
        status: 'missing_migration',
        guestSecretConfigured,
        serviceClientConfigured: true,
        mode: prod ? 'fail_closed' : 'local_dev',
        detail: 'Quota migration 0006 tables/RPCs are missing in Supabase.',
      };
    }

    return {
      status: 'unavailable',
      guestSecretConfigured,
      serviceClientConfigured: true,
      mode: prod ? 'fail_closed' : 'local_dev',
      detail: `Quota storage probe failed: ${redactSecrets(String(error.message || 'rpc_error')).slice(0, 120)}`,
    };
  } catch (err: unknown) {
    return {
      status: 'unavailable',
      guestSecretConfigured,
      serviceClientConfigured: true,
      mode: prod ? 'fail_closed' : 'local_dev',
      detail: `Quota storage probe timed out or failed: ${redactSecrets(
        err instanceof Error ? err.message : String(err)
      ).slice(0, 120)}`,
    };
  }
}

export function buildQuotaErrorResponse(outcome: QuotaCheckOutcome): NextResponse {
  const response = NextResponse.json(
    {
      error: redactSecrets(
        outcome.error ||
          'Investigation quota unavailable or exhausted. Please sign in or retry later.'
      ),
      errorCode: outcome.errorCode || 'quota_exhausted',
      capability: outcome.capability,
      requiresRegistration: outcome.requiresRegistration ?? false,
      requiresVerification: outcome.requiresVerification ?? false,
      quota: outcome.snapshot,
    },
    {
      status: outcome.status,
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        Vary: 'Cookie',
      },
    }
  );

  return attachGuestCookie(response, outcome.cookieToSet);
}
