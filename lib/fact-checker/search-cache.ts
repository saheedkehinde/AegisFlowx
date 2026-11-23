import { createHash } from 'node:crypto';
import { createClient as createSupabaseClient, type SupabaseClient } from '@supabase/supabase-js';
import { redactSecrets } from '@/lib/model-config';

export type SearchCacheProvider = 'serper' | 'urlhaus' | 'wikipedia';

const ALLOWED_PROVIDERS = new Set<SearchCacheProvider>(['serper', 'urlhaus', 'wikipedia']);

export interface PersistentCacheRecord<T = Record<string, unknown>> {
  payload: T;
  cachedAt: string;
  expiresAt: string;
}

/**
 * Derives a deterministic SHA-256 cache key so normalized queries never leak
 * raw strings or oversized identifiers in the primary key.
 */
export function deriveSearchCacheKey(provider: SearchCacheProvider, rawKey: string): string {
  if (!ALLOWED_PROVIDERS.has(provider)) {
    throw new Error(`Unsupported search cache provider: ${String(provider)}`);
  }
  const normalized = `${provider}:${String(rawKey || '').trim().toLowerCase()}`;
  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/**
 * Creates a strictly server-only Supabase service-role client for trusted
 * cache reads and writes with session persistence disabled.
 * Returns null if running outside a trusted server environment or unconfigured.
 */
export function getSearchCacheServiceClient(env: NodeJS.ProcessEnv = process.env): SupabaseClient | null {
  if (typeof window !== 'undefined') {
    return null;
  }

  const url = env.NEXT_PUBLIC_SUPABASE_URL;
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
  });
}

/**
 * Reads an unexpired entry from `public.search_cache` using the trusted
 * server-only service-role client. Fails closed (returns null) if unconfigured,
 * expired, malformed, or unreachable so upstream searches proceed normally.
 */
export async function readPersistentSearchCache<T = Record<string, unknown>>(
  provider: SearchCacheProvider,
  rawKey: string,
  clientOverride?: SupabaseClient | null
): Promise<PersistentCacheRecord<T> | null> {
  if (!ALLOWED_PROVIDERS.has(provider) || !rawKey || typeof rawKey !== 'string') {
    return null;
  }

  const client = clientOverride !== undefined ? clientOverride : getSearchCacheServiceClient();
  if (!client) {
    return null;
  }

  try {
    const cacheKey = deriveSearchCacheKey(provider, rawKey);
    const nowIso = new Date().toISOString();

    const { data, error } = await client
      .from('search_cache')
      .select('response_payload, cached_at, expires_at')
      .eq('cache_key', cacheKey)
      .eq('provider', provider)
      .gt('expires_at', nowIso)
      .maybeSingle();

    if (error || !data || !data.response_payload || typeof data.response_payload !== 'object') {
      return null;
    }

    const expiresMs = Date.parse(String(data.expires_at || ''));
    if (!Number.isFinite(expiresMs) || expiresMs <= Date.now()) {
      return null;
    }

    return {
      payload: data.response_payload as T,
      cachedAt: String(data.cached_at || nowIso),
      expiresAt: String(data.expires_at),
    };
  } catch {
    return null;
  }
}

/**
 * Persists a validated research payload to `public.search_cache` using the
 * trusted server-only service-role client. Never caches failed requests and
 * redacts any accidental secret tokens before storage.
 */
export async function writePersistentSearchCache<T extends Record<string, unknown>>(
  provider: SearchCacheProvider,
  rawKey: string,
  queryNormalized: string,
  payload: T,
  ttlMs: number,
  clientOverride?: SupabaseClient | null
): Promise<boolean> {
  if (
    !ALLOWED_PROVIDERS.has(provider) ||
    !rawKey ||
    typeof rawKey !== 'string' ||
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    !Number.isFinite(ttlMs) ||
    ttlMs <= 0
  ) {
    return false;
  }

  const client = clientOverride !== undefined ? clientOverride : getSearchCacheServiceClient();
  if (!client) {
    return false;
  }

  try {
    const cacheKey = deriveSearchCacheKey(provider, rawKey);
    const safeQuery = String(queryNormalized || rawKey).trim().slice(0, 160);
    const sanitizedPayload = JSON.parse(redactSecrets(JSON.stringify(payload))) as T;

    const nowMs = Date.now();
    const cachedAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(nowMs + ttlMs).toISOString();

    const { error } = await client.from('search_cache').upsert(
      {
        cache_key: cacheKey,
        provider,
        query_normalized: safeQuery,
        response_payload: sanitizedPayload,
        cached_at: cachedAt,
        expires_at: expiresAt,
      },
      { onConflict: 'cache_key' }
    );

    return !error;
  } catch {
    return false;
  }
}
